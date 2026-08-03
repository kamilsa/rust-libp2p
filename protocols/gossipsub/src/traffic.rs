// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Per-topic gossipsub traffic accounting, split by direction and by
//! data/control class.
//!
//! This is a always-on, allocation-light counterpart to the optional
//! (Prometheus-backed) `metrics` module: it exists so an embedding application
//! can attribute *every* byte gossipsub puts on, or takes off, the wire to a
//! topic and a class — including the control messages (GRAFT/PRUNE/IHAVE/
//! IWANT/IDONTWANT/subscriptions) that never surface as [`crate::Event`]s.
//!
//! # Semantics
//!
//! - **Byte counts are protobuf payload bytes.** Length-prefix framing and
//!   transport (TCP/QUIC) overhead are *not* included, so these are
//!   gossipsub-layer figures rather than NIC-level ones.
//! - **Outbound is counted at enqueue time**, when an RPC is accepted into a
//!   peer's send queue — not when the bytes reach the socket. Under a
//!   bandwidth-constrained link the wire can lag the enqueue substantially, so
//!   the outbound series describes *offered load*. Messages the queue rejects
//!   (queue full) are never counted, and publishes later dropped on timeout are
//!   subtracted again, so the *volume* is accurate even though the *timing* is
//!   optimistic.
//! - **Inbound is counted at decode time**, which is genuine wire-arrival.
//!
//! # Topic attribution
//!
//! IWANT, IDONTWANT and the extension handshake carry no topic on the wire.
//! Outbound, the topic is supplied by the call site (which always knows it), so
//! attribution is exact. Inbound, it can only be recovered by resolving message
//! ids against the local message cache; whatever cannot be resolved is booked to
//! [`GossipTrafficStats::untopiced`], as is the topic-less extension handshake.

use std::collections::HashMap;

use prost::Message as _;

use crate::{
    MessageId, TopicHash,
    rpc_proto::proto,
    types::{ControlAction, RawMessage, RpcOut, Subscription, SubscriptionAction},
};

/// The class of a gossipsub control message, for the control-vs-data split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlKind {
    /// IHAVE — advertises message ids we hold on a topic.
    IHave,
    /// IWANT — requests message ids advertised to us.
    IWant,
    /// GRAFT — asks to be added to a peer's mesh for a topic.
    Graft,
    /// PRUNE — asks to be removed from a peer's mesh for a topic.
    Prune,
    /// IDONTWANT — asks a peer not to forward message ids we already have.
    IDontWant,
    /// Topic subscribe/unsubscribe announcements.
    Subscription,
    /// The gossipsub extension handshake. Never carries a topic.
    Extensions,
}

impl ControlKind {
    /// Number of distinct control kinds; the width of the per-kind arrays.
    pub const COUNT: usize = 7;

    /// Dense index of this kind, used to address the per-kind arrays.
    pub const fn index(self) -> usize {
        match self {
            ControlKind::IHave => 0,
            ControlKind::IWant => 1,
            ControlKind::Graft => 2,
            ControlKind::Prune => 3,
            ControlKind::IDontWant => 4,
            ControlKind::Subscription => 5,
            ControlKind::Extensions => 6,
        }
    }

    /// All kinds, in index order — handy for labelled iteration by consumers.
    pub const ALL: [ControlKind; Self::COUNT] = [
        ControlKind::IHave,
        ControlKind::IWant,
        ControlKind::Graft,
        ControlKind::Prune,
        ControlKind::IDontWant,
        ControlKind::Subscription,
        ControlKind::Extensions,
    ];

    /// Lowercase name, for log/metric labels.
    pub const fn as_str(self) -> &'static str {
        match self {
            ControlKind::IHave => "ihave",
            ControlKind::IWant => "iwant",
            ControlKind::Graft => "graft",
            ControlKind::Prune => "prune",
            ControlKind::IDontWant => "idontwant",
            ControlKind::Subscription => "subscription",
            ControlKind::Extensions => "extensions",
        }
    }
}

/// Byte and message counters for one topic in one direction.
///
/// "Data" is application payload: the body of a published message, or the cell
/// body of a partial message. "Meta" is partial-message metadata (the
/// available/requested bitmaps and headers) — carried on a data topic but not
/// itself application payload, so it is kept separate and counted as overhead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficCounters {
    /// Published-message payload bytes plus partial-message body bytes.
    pub data_bytes: u64,
    /// Number of RPCs contributing to `data_bytes`.
    pub data_msgs: u64,
    /// Partial-message metadata bytes (bitmaps, headers).
    pub meta_bytes: u64,
    /// Number of RPCs contributing to `meta_bytes`.
    pub meta_msgs: u64,
    /// Control bytes, indexed by [`ControlKind::index`].
    pub control_bytes: [u64; ControlKind::COUNT],
    /// Control message counts, indexed by [`ControlKind::index`].
    pub control_msgs: [u64; ControlKind::COUNT],
}

impl TrafficCounters {
    /// Add `bytes` of application payload.
    pub(crate) fn add_data(&mut self, bytes: usize) {
        self.data_bytes = self.data_bytes.saturating_add(bytes as u64);
        self.data_msgs = self.data_msgs.saturating_add(1);
    }

    /// Remove `bytes` of application payload, for an enqueued message that was
    /// dropped before it could be sent.
    pub(crate) fn sub_data(&mut self, bytes: usize) {
        self.data_bytes = self.data_bytes.saturating_sub(bytes as u64);
        self.data_msgs = self.data_msgs.saturating_sub(1);
    }

    /// Add `bytes` of partial-message metadata.
    pub(crate) fn add_meta(&mut self, bytes: usize) {
        self.meta_bytes = self.meta_bytes.saturating_add(bytes as u64);
        self.meta_msgs = self.meta_msgs.saturating_add(1);
    }

    /// Add `bytes` of control traffic of the given kind.
    pub(crate) fn add_control(&mut self, kind: ControlKind, bytes: usize) {
        let i = kind.index();
        self.control_bytes[i] = self.control_bytes[i].saturating_add(bytes as u64);
        self.control_msgs[i] = self.control_msgs[i].saturating_add(1);
    }

    /// Total control bytes across all kinds.
    pub fn control_bytes_total(&self) -> u64 {
        self.control_bytes.iter().copied().sum()
    }

    /// Total control messages across all kinds.
    pub fn control_msgs_total(&self) -> u64 {
        self.control_msgs.iter().copied().sum()
    }

    /// Every byte accounted in this direction: payload, partial metadata and
    /// control.
    pub fn total_bytes(&self) -> u64 {
        self.data_bytes
            .saturating_add(self.meta_bytes)
            .saturating_add(self.control_bytes_total())
    }
}

/// Send and receive counters for a single topic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectionalTraffic {
    /// Bytes enqueued for sending to peers.
    pub tx: TrafficCounters,
    /// Bytes received from peers.
    pub rx: TrafficCounters,
}

/// Cumulative gossipsub traffic, per topic, since the behaviour was created.
///
/// Obtained from [`crate::Behaviour::traffic`]. Counters only ever grow (bar the
/// dropped-publish correction), so an embedding application samples this
/// periodically and diffs consecutive snapshots to get a rate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GossipTrafficStats {
    /// Traffic attributed to a specific topic.
    pub per_topic: HashMap<TopicHash, DirectionalTraffic>,
    /// Traffic that carries no topic on the wire and could not be attributed:
    /// the extension handshake, and inbound IWANT/IDONTWANT whose message ids
    /// are not in the local message cache.
    pub untopiced: DirectionalTraffic,
}

impl GossipTrafficStats {
    /// Mutable send counters for a topic, creating the entry if needed.
    pub(crate) fn tx_mut(&mut self, topic: &TopicHash) -> &mut TrafficCounters {
        &mut self.entry(topic).tx
    }

    /// Mutable receive counters for a topic, creating the entry if needed.
    pub(crate) fn rx_mut(&mut self, topic: &TopicHash) -> &mut TrafficCounters {
        &mut self.entry(topic).rx
    }

    fn entry(&mut self, topic: &TopicHash) -> &mut DirectionalTraffic {
        // `TopicHash` is only cloned the first time a topic is seen.
        if !self.per_topic.contains_key(topic) {
            self.per_topic.insert(topic.clone(), Default::default());
        }
        self.per_topic
            .get_mut(topic)
            .expect("entry inserted just above")
    }

    /// Summed send counters across every topic plus the untopiced bucket.
    pub fn total_tx(&self) -> TrafficCounters {
        self.fold(|d| &d.tx)
    }

    /// Summed receive counters across every topic plus the untopiced bucket.
    pub fn total_rx(&self) -> TrafficCounters {
        self.fold(|d| &d.rx)
    }

    fn fold(&self, pick: impl Fn(&DirectionalTraffic) -> &TrafficCounters) -> TrafficCounters {
        let mut acc = TrafficCounters::default();
        for counters in self
            .per_topic
            .values()
            .map(&pick)
            .chain(std::iter::once(pick(&self.untopiced)))
        {
            acc.data_bytes = acc.data_bytes.saturating_add(counters.data_bytes);
            acc.data_msgs = acc.data_msgs.saturating_add(counters.data_msgs);
            acc.meta_bytes = acc.meta_bytes.saturating_add(counters.meta_bytes);
            acc.meta_msgs = acc.meta_msgs.saturating_add(counters.meta_msgs);
            for i in 0..ControlKind::COUNT {
                acc.control_bytes[i] =
                    acc.control_bytes[i].saturating_add(counters.control_bytes[i]);
                acc.control_msgs[i] = acc.control_msgs[i].saturating_add(counters.control_msgs[i]);
            }
        }
        acc
    }
}

/// How to attribute an outbound RPC that carries no topic on the wire.
///
/// GRAFT/PRUNE/IHAVE/subscriptions name their topic in the message itself and
/// ignore this; only IWANT and IDONTWANT need it.
pub(crate) enum Attribution<'a> {
    /// No topic is known — book to [`GossipTrafficStats::untopiced`].
    None,
    /// The whole RPC concerns one topic.
    Topic(&'a TopicHash),
    /// The RPC batches message ids drawn from several topics; each id is
    /// attributed via this map and the residual framing goes to `untopiced`.
    PerMessage(&'a HashMap<MessageId, TopicHash>),
}

/// Encoded size of a protobuf `bytes`/`string` field: tag + length varint +
/// payload. Used to split a batched control message across topics.
///
/// Every field this module measures sits at tag 1..=15, so the tag is one byte.
fn len_delimited_field_len(len: usize) -> usize {
    1 + prost::encoding::encoded_len_varint(len as u64) + len
}

/// Protobuf-encoded size of a published message, without allocating.
///
/// [`RawMessage::raw_protobuf_len`] builds a whole `proto::Message` to measure
/// it, which clones the payload — far too expensive to do on every send of a
/// multi-kilobyte message. `proto::Message` is six length-delimited fields at
/// tags 1..=6, so the size follows directly from the field lengths.
fn message_encoded_len(message: &RawMessage) -> usize {
    let mut len = len_delimited_field_len(message.topic.as_str().len());
    if let Some(from) = message.source.as_ref() {
        // `PeerId::to_bytes` is an allocation, but a small fixed one; its length
        // is what we need and there is no borrowing accessor.
        len += len_delimited_field_len(from.to_bytes().len());
    }
    len += len_delimited_field_len(message.data.len());
    if message.sequence_number.is_some() {
        len += len_delimited_field_len(8);
    }
    if let Some(signature) = message.signature.as_ref() {
        len += len_delimited_field_len(signature.len());
    }
    if let Some(key) = message.key.as_ref() {
        len += len_delimited_field_len(key.len());
    }
    len
}

/// A measured, topic-attributed traffic contribution, decoupled from the
/// counters it will land in.
///
/// Outbound accounting has to measure an RPC *before* it is moved into the send
/// queue, but must only commit once the queue has accepted it — hence the split
/// between [`classify_outbound`] and [`Contribution::apply_tx`].
#[derive(Debug, Default)]
pub(crate) enum Contribution {
    #[default]
    None,
    Data {
        topic: TopicHash,
        bytes: usize,
    },
    Partial {
        topic: TopicHash,
        body: usize,
        meta: usize,
    },
    Control {
        topic: Option<TopicHash>,
        kind: ControlKind,
        bytes: usize,
    },
    /// A single frame spanning several topics (`SubscribeMany`, or an IWANT
    /// batch drawn from more than one topic).
    Many(Vec<(Option<TopicHash>, ControlKind, usize)>),
}

impl Contribution {
    /// Commit this contribution to the send counters.
    pub(crate) fn apply_tx(self, stats: &mut GossipTrafficStats) {
        match self {
            Contribution::None => {}
            Contribution::Data { topic, bytes } => stats.tx_mut(&topic).add_data(bytes),
            Contribution::Partial { topic, body, meta } => {
                let counters = stats.tx_mut(&topic);
                if body > 0 {
                    counters.add_data(body);
                }
                if meta > 0 {
                    counters.add_meta(meta);
                }
            }
            Contribution::Control { topic, kind, bytes } => match topic {
                Some(topic) => stats.tx_mut(&topic).add_control(kind, bytes),
                None => stats.untopiced.tx.add_control(kind, bytes),
            },
            Contribution::Many(parts) => {
                for (topic, kind, bytes) in parts {
                    match topic {
                        Some(topic) => stats.tx_mut(&topic).add_control(kind, bytes),
                        None => stats.untopiced.tx.add_control(kind, bytes),
                    }
                }
            }
        }
    }
}

/// Exact protobuf-encoded size of an outbound RPC.
///
/// Control RPCs are small, so cloning them to measure is cheap. `Publish` and
/// partial messages are not cloned: their size is taken from the payload
/// directly, which is what we want to attribute anyway.
fn control_encoded_len(rpc: &RpcOut) -> usize {
    match rpc {
        RpcOut::Publish { .. } => 0,
        #[cfg(feature = "partial-messages")]
        RpcOut::PartialMessage(_) => 0,
        other => clone_control(other).map_or(0, |rpc| rpc.into_protobuf().encoded_len()),
    }
}

/// Clone a control-class `RpcOut`. Returns `None` for the payload-carrying
/// variants, which must never be cloned.
fn clone_control(rpc: &RpcOut) -> Option<RpcOut> {
    Some(match rpc {
        RpcOut::Subscribe {
            topic,
            requests_partial,
            supports_partial,
        } => RpcOut::Subscribe {
            topic: topic.clone(),
            requests_partial: *requests_partial,
            supports_partial: *supports_partial,
        },
        RpcOut::SubscribeMany(topics) => RpcOut::SubscribeMany(topics.clone()),
        RpcOut::Unsubscribe(topic) => RpcOut::Unsubscribe(topic.clone()),
        RpcOut::Graft(graft) => RpcOut::Graft(graft.clone()),
        RpcOut::Prune(prune) => RpcOut::Prune(prune.clone()),
        RpcOut::IHave(ihave) => RpcOut::IHave(ihave.clone()),
        RpcOut::IWant(iwant) => RpcOut::IWant(iwant.clone()),
        RpcOut::IDontWant(idontwant) => RpcOut::IDontWant(idontwant.clone()),
        RpcOut::Extensions(extensions) => RpcOut::Extensions(*extensions),
        RpcOut::TestExtension => RpcOut::TestExtension,
        RpcOut::Publish { .. } => return None,
        #[cfg(feature = "partial-messages")]
        RpcOut::PartialMessage(_) => return None,
    })
}

/// Measure an outbound RPC and work out which topic(s) it belongs to.
///
/// Call before handing the RPC to the send queue; commit the result with
/// [`Contribution::apply_tx`] only if the queue accepts it.
pub(crate) fn classify_outbound(rpc: &RpcOut, attribution: Attribution<'_>) -> Contribution {
    match rpc {
        RpcOut::Publish { message, .. } => Contribution::Data {
            topic: message.topic.clone(),
            bytes: message_encoded_len(message),
        },
        #[cfg(feature = "partial-messages")]
        RpcOut::PartialMessage(partial) => Contribution::Partial {
            topic: partial.topic_hash.clone(),
            body: partial.body.as_ref().map_or(0, Vec::len),
            meta: partial.metadata.as_ref().map_or(0, Vec::len),
        },
        RpcOut::Subscribe { topic, .. } => Contribution::Control {
            topic: Some(topic.clone()),
            kind: ControlKind::Subscription,
            bytes: control_encoded_len(rpc),
        },
        RpcOut::Unsubscribe(topic) => Contribution::Control {
            topic: Some(topic.clone()),
            kind: ControlKind::Subscription,
            bytes: control_encoded_len(rpc),
        },
        RpcOut::SubscribeMany(topics) => {
            // One frame, many topics: charge each topic its own SubOpts, and
            // fold the residual framing into the first so the parts still sum
            // to the frame.
            let total = control_encoded_len(rpc);
            let mut attributed = 0;
            let mut parts = Vec::with_capacity(topics.len());
            for (topic, requests_partial, supports_partial) in topics {
                let opts = proto::SubOpts {
                    subscribe: Some(true),
                    topic_id: Some(topic.clone().into_string()),
                    requests_partial: Some(*requests_partial),
                    supports_partial: Some(*supports_partial),
                };
                let bytes = len_delimited_field_len(opts.encoded_len());
                attributed += bytes;
                parts.push((Some(topic.clone()), ControlKind::Subscription, bytes));
            }
            if let Some(first) = parts.first_mut() {
                first.2 += total.saturating_sub(attributed);
            }
            Contribution::Many(parts)
        }
        RpcOut::Graft(graft) => Contribution::Control {
            topic: Some(graft.topic_hash.clone()),
            kind: ControlKind::Graft,
            bytes: control_encoded_len(rpc),
        },
        RpcOut::Prune(prune) => Contribution::Control {
            topic: Some(prune.topic_hash.clone()),
            kind: ControlKind::Prune,
            bytes: control_encoded_len(rpc),
        },
        RpcOut::IHave(ihave) => Contribution::Control {
            topic: Some(ihave.topic_hash.clone()),
            kind: ControlKind::IHave,
            bytes: control_encoded_len(rpc),
        },
        RpcOut::IWant(iwant) => classify_id_batch(
            ControlKind::IWant,
            control_encoded_len(rpc),
            &iwant.message_ids,
            attribution,
        ),
        RpcOut::IDontWant(idontwant) => classify_id_batch(
            ControlKind::IDontWant,
            control_encoded_len(rpc),
            &idontwant.message_ids,
            attribution,
        ),
        RpcOut::Extensions(_) | RpcOut::TestExtension => Contribution::Control {
            topic: None,
            kind: ControlKind::Extensions,
            bytes: control_encoded_len(rpc),
        },
    }
}

/// Measure a batch of message ids (IWANT/IDONTWANT), splitting per topic when
/// the batch spans several.
fn classify_id_batch(
    kind: ControlKind,
    total: usize,
    message_ids: &[MessageId],
    attribution: Attribution<'_>,
) -> Contribution {
    match attribution {
        Attribution::Topic(topic) => Contribution::Control {
            topic: Some(topic.clone()),
            kind,
            bytes: total,
        },
        Attribution::None => Contribution::Control {
            topic: None,
            kind,
            bytes: total,
        },
        Attribution::PerMessage(map) => {
            let mut parts: Vec<(Option<TopicHash>, ControlKind, usize)> = Vec::new();
            let mut attributed = 0;
            for id in message_ids {
                let Some(topic) = map.get(id) else { continue };
                let bytes = len_delimited_field_len(id.0.len());
                attributed += bytes;
                match parts.iter_mut().find(|(t, _, _)| t.as_ref() == Some(topic)) {
                    Some(part) => part.2 += bytes,
                    None => parts.push((Some(topic.clone()), kind, bytes)),
                }
            }
            // Framing, plus any ids we could not attribute.
            let residual = total.saturating_sub(attributed);
            if residual > 0 || parts.is_empty() {
                parts.push((None, kind, residual));
            }
            Contribution::Many(parts)
        }
    }
}

/// Un-book an outbound publish that was enqueued but dropped before it could be
/// sent (its send timeout elapsed while it sat in the queue).
pub(crate) fn account_outbound_dropped(stats: &mut GossipTrafficStats, rpc: &RpcOut) {
    if let RpcOut::Publish { message, .. } = rpc {
        stats
            .tx_mut(&message.topic)
            .sub_data(message_encoded_len(message));
    }
}

/// Book an inbound published message.
pub(crate) fn account_inbound_message(stats: &mut GossipTrafficStats, message: &RawMessage) {
    stats
        .rx_mut(&message.topic)
        .add_data(message_encoded_len(message));
}

/// Book an inbound subscription announcement.
pub(crate) fn account_inbound_subscription(
    stats: &mut GossipTrafficStats,
    subscription: &Subscription,
) {
    let subscribe = matches!(subscription.action, SubscriptionAction::Subscribe);
    let opts = proto::SubOpts {
        subscribe: Some(subscribe),
        topic_id: Some(subscription.topic_hash.clone().into_string()),
        requests_partial: subscribe.then_some(subscription.options.requests_partial),
        supports_partial: subscribe.then_some(subscription.options.supports_partial),
    };
    let bytes = len_delimited_field_len(opts.encoded_len());
    stats
        .rx_mut(&subscription.topic_hash)
        .add_control(ControlKind::Subscription, bytes);
}

/// Book an inbound partial message.
#[cfg(feature = "partial-messages")]
pub(crate) fn account_inbound_partial(
    stats: &mut GossipTrafficStats,
    partial: &crate::extensions::partial_messages::PartialMessage,
) {
    let counters = stats.rx_mut(&partial.topic_hash);
    if let Some(body) = partial.body.as_ref() {
        counters.add_data(body.len());
    }
    if let Some(metadata) = partial.metadata.as_ref() {
        counters.add_meta(metadata.len());
    }
}

/// Book an inbound control message.
///
/// `resolve` maps a message id back to its topic via the local message cache;
/// IWANT/IDONTWANT carry no topic on the wire, so ids it cannot resolve are
/// booked to `untopiced`.
pub(crate) fn account_inbound_control(
    stats: &mut GossipTrafficStats,
    control: &ControlAction,
    resolve: impl Fn(&MessageId) -> Option<TopicHash>,
) {
    match control {
        ControlAction::IHave(ihave) => {
            let bytes = proto::ControlIHave {
                topic_id: Some(ihave.topic_hash.clone().into_string()),
                message_ids: ihave.message_ids.iter().map(|id| id.0.clone()).collect(),
            }
            .encoded_len();
            stats
                .rx_mut(&ihave.topic_hash)
                .add_control(ControlKind::IHave, len_delimited_field_len(bytes));
        }
        ControlAction::Graft(graft) => {
            let bytes = proto::ControlGraft {
                topic_id: Some(graft.topic_hash.clone().into_string()),
            }
            .encoded_len();
            stats
                .rx_mut(&graft.topic_hash)
                .add_control(ControlKind::Graft, len_delimited_field_len(bytes));
        }
        ControlAction::Prune(prune) => {
            let bytes = proto::ControlPrune {
                topic_id: Some(prune.topic_hash.clone().into_string()),
                peers: prune
                    .peers
                    .iter()
                    .map(|info| proto::PeerInfo {
                        peer_id: info.peer_id.map(|id| id.to_bytes()),
                        signed_peer_record: None,
                    })
                    .collect(),
                backoff: prune.backoff,
            }
            .encoded_len();
            stats
                .rx_mut(&prune.topic_hash)
                .add_control(ControlKind::Prune, len_delimited_field_len(bytes));
        }
        ControlAction::IWant(iwant) => {
            account_inbound_id_batch(stats, ControlKind::IWant, &iwant.message_ids, resolve);
        }
        ControlAction::IDontWant(idontwant) => {
            account_inbound_id_batch(
                stats,
                ControlKind::IDontWant,
                &idontwant.message_ids,
                resolve,
            );
        }
        ControlAction::Extensions(extensions) => {
            // The extension handshake is a handful of bytes and has no topic.
            let bytes = proto::ControlExtensions {
                partial_messages: extensions.and_then(|e| e.partial_messages),
            }
            .encoded_len();
            stats
                .untopiced
                .rx
                .add_control(ControlKind::Extensions, len_delimited_field_len(bytes));
        }
    }
}

fn account_inbound_id_batch(
    stats: &mut GossipTrafficStats,
    kind: ControlKind,
    message_ids: &[MessageId],
    resolve: impl Fn(&MessageId) -> Option<TopicHash>,
) {
    for id in message_ids {
        let bytes = len_delimited_field_len(id.0.len());
        match resolve(id) {
            Some(topic) => stats.rx_mut(&topic).add_control(kind, bytes),
            None => stats.untopiced.rx.add_control(kind, bytes),
        }
    }
}
