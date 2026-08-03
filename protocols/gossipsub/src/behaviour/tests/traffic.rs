// Copyright 2025 Sigma Prime Pty Ltd.
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

//! Tests for per-topic traffic accounting ([`crate::Behaviour::traffic`]).

use libp2p_identity::PeerId;
use libp2p_swarm::{ConnectionId, NetworkBehaviour};

use super::DefaultBehaviourTestBuilder;
use crate::{
    ControlKind, IdentTopic,
    config::{Config, ConfigBuilder},
    handler::HandlerEvent,
    types::{
        ControlAction, Graft, IDontWant, IHave, MessageId, PeerKind, RawMessage, RpcIn, RpcOut,
        Subscription, SubscriptionAction, SubscriptionOpts,
    },
};

/// A published message is booked as data on its own topic, and nothing else.
#[test]
fn test_traffic_publish_is_data_on_its_topic() {
    let (mut gs, _peers, _queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(3)
        .topics(vec!["topic1".into(), "topic2".into()])
        .to_subscribe(true)
        .create_network();

    gs.publish(topics[0].clone(), vec![7u8; 512])
        .expect("publish should succeed");

    let traffic = gs.traffic();
    let published = traffic
        .per_topic
        .get(&topics[0])
        .expect("published topic should be tracked");

    // Fanned out to every mesh peer, so the payload is counted once per peer.
    assert!(published.tx.data_msgs >= 1);
    assert!(
        published.tx.data_bytes >= 512 * published.tx.data_msgs,
        "each copy should carry at least the payload"
    );
    assert_eq!(
        published.tx.control_bytes[ControlKind::IHave.index()],
        0,
        "publishing must not be booked as control"
    );

    // The other topic saw no data.
    let other = traffic.per_topic.get(&topics[1]);
    assert_eq!(other.map_or(0, |t| t.tx.data_bytes), 0);
}

/// GRAFT/PRUNE/IHAVE are booked as control against the topic they name, kept
/// separate from payload.
#[test]
fn test_traffic_control_is_attributed_per_topic() {
    let (mut gs, peers, _queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["topic1".into()])
        .to_subscribe(true)
        .create_network();

    let before = gs
        .traffic()
        .per_topic
        .get(&topics[0])
        .map_or(0, |t| t.rx.control_bytes[ControlKind::Graft.index()]);

    gs.on_connection_handler_event(
        peers[0],
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![],
                subscriptions: vec![],
                control_msgs: vec![ControlAction::Graft(Graft {
                    topic_hash: topics[0].clone(),
                })],
                #[cfg(feature = "partial-messages")]
                partial_message: None,
            },
            invalid_messages: vec![],
        },
    );

    let after = gs.traffic().per_topic.get(&topics[0]).unwrap();
    assert!(
        after.rx.control_bytes[ControlKind::Graft.index()] > before,
        "inbound GRAFT should be booked as control on its topic"
    );
    assert_eq!(
        after.rx.data_bytes, 0,
        "control must not be counted as payload"
    );
}

/// An inbound IHAVE names its topic, so its bytes are attributable even though
/// it carries only message ids.
#[test]
fn test_traffic_inbound_ihave_attributed() {
    let (mut gs, peers, _queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["topic1".into()])
        .to_subscribe(true)
        .create_network();

    gs.on_connection_handler_event(
        peers[0],
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![],
                subscriptions: vec![],
                control_msgs: vec![ControlAction::IHave(IHave {
                    topic_hash: topics[0].clone(),
                    message_ids: vec![MessageId::new(b"abcdefgh"), MessageId::new(b"ijklmnop")],
                })],
                #[cfg(feature = "partial-messages")]
                partial_message: None,
            },
            invalid_messages: vec![],
        },
    );

    let counters = &gs.traffic().per_topic.get(&topics[0]).unwrap().rx;
    assert!(counters.control_bytes[ControlKind::IHave.index()] >= 16);
    assert_eq!(counters.control_msgs[ControlKind::IHave.index()], 1);
}

/// An inbound IDONTWANT carries no topic; with nothing in the message cache to
/// resolve its ids, it lands in the untopiced bucket rather than being dropped.
#[test]
fn test_traffic_unresolvable_idontwant_is_untopiced() {
    let (mut gs, peers, _queues, _topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["topic1".into()])
        .to_subscribe(true)
        .peer_kind(PeerKind::Gossipsubv1_2)
        .create_network();

    let before = gs.traffic().untopiced.rx.control_bytes[ControlKind::IDontWant.index()];

    gs.on_connection_handler_event(
        peers[0],
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![],
                subscriptions: vec![],
                control_msgs: vec![ControlAction::IDontWant(IDontWant {
                    message_ids: vec![MessageId::new(b"not-in-cache")],
                })],
                #[cfg(feature = "partial-messages")]
                partial_message: None,
            },
            invalid_messages: vec![],
        },
    );

    assert!(
        gs.traffic().untopiced.rx.control_bytes[ControlKind::IDontWant.index()] > before,
        "an unattributable IDONTWANT should still be counted, as untopiced"
    );
}

/// An outbound IDONTWANT triggered by a received message is attributed to that
/// message's topic, even though the wire format cannot express it.
#[test]
fn test_traffic_outbound_idontwant_attributed_to_topic() {
    let config = ConfigBuilder::default()
        .idontwant_message_size_threshold(100)
        .build()
        .unwrap();
    let (mut gs, peers, _queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(5)
        .topics(vec!["topic1".into()])
        .to_subscribe(true)
        .gs_config(config)
        .peer_kind(PeerKind::Gossipsubv1_2)
        .create_network();

    let message = RawMessage {
        source: Some(peers[1]),
        data: vec![12u8; 1024],
        sequence_number: Some(0),
        topic: topics[0].clone(),
        signature: None,
        key: None,
        validated: true,
    };
    gs.handle_received_message(message, &PeerId::random());

    let counters = &gs.traffic().per_topic.get(&topics[0]).unwrap().tx;
    assert!(
        counters.control_bytes[ControlKind::IDontWant.index()] > 0,
        "outbound IDONTWANT should be attributed to the message's topic"
    );
    assert_eq!(
        gs.traffic().untopiced.tx.control_bytes[ControlKind::IDontWant.index()],
        0,
        "the topic is known at the call site, so nothing should be untopiced"
    );
}

/// Inbound subscriptions are control traffic on the topic they name.
#[test]
fn test_traffic_inbound_subscription_is_control() {
    let (mut gs, peers, _queues, _topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec![])
        .to_subscribe(false)
        .gs_config(Config::default())
        .create_network();

    let topic = IdentTopic::new("subscribed-topic").hash();
    gs.on_connection_handler_event(
        peers[0],
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![],
                subscriptions: vec![Subscription {
                    action: SubscriptionAction::Subscribe,
                    topic_hash: topic.clone(),
                    options: SubscriptionOpts::default(),
                }],
                control_msgs: vec![],
                #[cfg(feature = "partial-messages")]
                partial_message: None,
            },
            invalid_messages: vec![],
        },
    );

    let counters = &gs.traffic().per_topic.get(&topic).unwrap().rx;
    assert!(counters.control_bytes[ControlKind::Subscription.index()] > 0);
    assert_eq!(counters.data_bytes, 0);
}

/// An inbound published message is booked as received payload on its topic.
#[test]
fn test_traffic_inbound_message_is_data() {
    let (mut gs, peers, _queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["topic1".into()])
        .to_subscribe(true)
        .create_network();

    gs.on_connection_handler_event(
        peers[0],
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![RawMessage {
                    source: Some(peers[0]),
                    data: vec![3u8; 2048],
                    sequence_number: Some(1),
                    topic: topics[0].clone(),
                    signature: None,
                    key: None,
                    validated: true,
                }],
                subscriptions: vec![],
                control_msgs: vec![],
                #[cfg(feature = "partial-messages")]
                partial_message: None,
            },
            invalid_messages: vec![],
        },
    );

    let counters = &gs.traffic().per_topic.get(&topics[0]).unwrap().rx;
    assert!(
        counters.data_bytes >= 2048,
        "received payload should be booked as data"
    );
    assert_eq!(counters.data_msgs, 1);
    assert_eq!(counters.control_bytes_total(), 0);
}

/// `total_bytes` must equal payload + partial metadata + every control kind, so
/// a breakdown always reconciles against the total.
#[test]
fn test_traffic_totals_reconcile() {
    let (mut gs, peers, _queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(3)
        .topics(vec!["topic1".into()])
        .to_subscribe(true)
        .create_network();

    gs.publish(topics[0].clone(), vec![1u8; 256])
        .expect("publish should succeed");
    gs.on_connection_handler_event(
        peers[0],
        ConnectionId::new_unchecked(0),
        HandlerEvent::Message {
            rpc: RpcIn {
                messages: vec![],
                subscriptions: vec![],
                control_msgs: vec![ControlAction::IHave(IHave {
                    topic_hash: topics[0].clone(),
                    message_ids: vec![MessageId::new(b"12345678")],
                })],
                #[cfg(feature = "partial-messages")]
                partial_message: None,
            },
            invalid_messages: vec![],
        },
    );

    for counters in gs
        .traffic()
        .per_topic
        .values()
        .flat_map(|t| [&t.tx, &t.rx])
        .chain([&gs.traffic().untopiced.tx, &gs.traffic().untopiced.rx])
    {
        assert_eq!(
            counters.total_bytes(),
            counters.data_bytes + counters.meta_bytes + counters.control_bytes_total(),
            "total must be the sum of its parts"
        );
    }

    let total_tx = gs.traffic().total_tx();
    let summed_tx: u64 = gs
        .traffic()
        .per_topic
        .values()
        .map(|t| t.tx.total_bytes())
        .sum::<u64>()
        + gs.traffic().untopiced.tx.total_bytes();
    assert_eq!(
        total_tx.total_bytes(),
        summed_tx,
        "total_tx should aggregate every topic plus untopiced"
    );
}

/// Bytes are only booked once the send queue accepts the RPC, so a full queue
/// must not inflate the counters.
#[test]
fn test_traffic_excludes_queue_full_send() {
    let config = ConfigBuilder::default()
        .connection_handler_queue_len(1)
        .build()
        .unwrap();
    let (mut gs, _peers, _queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["topic1".into()])
        .to_subscribe(true)
        .gs_config(config)
        .create_network();

    // Publish more than the queue can hold; the surplus is rejected.
    for _ in 0..8 {
        let _ = gs.publish(topics[0].clone(), vec![9u8; 1024]);
    }

    let counters = &gs.traffic().per_topic.get(&topics[0]).unwrap().tx;
    assert!(
        counters.data_msgs <= 2,
        "only RPCs the queue accepted should be counted, got {}",
        counters.data_msgs
    );
}

/// A publish dropped in the queue on timeout is un-booked, so enqueue-time
/// accounting still reports the right volume.
#[test]
fn test_traffic_dropped_publish_is_subtracted() {
    let (mut gs, peers, _queues, topics) = DefaultBehaviourTestBuilder::default()
        .peer_no(1)
        .topics(vec!["topic1".into()])
        .to_subscribe(true)
        .create_network();

    gs.publish(topics[0].clone(), vec![5u8; 1024])
        .expect("publish should succeed");
    let after_publish = gs.traffic().per_topic.get(&topics[0]).unwrap().tx;
    assert!(after_publish.data_bytes > 0);

    let dropped = RpcOut::Publish {
        message_id: MessageId::new(b"dropped"),
        message: RawMessage {
            source: None,
            data: vec![5u8; 1024],
            sequence_number: Some(0),
            topic: topics[0].clone(),
            signature: None,
            key: None,
            validated: true,
        },
        timeout: futures_timer::Delay::new(std::time::Duration::from_secs(0)),
    };
    gs.on_connection_handler_event(
        peers[0],
        ConnectionId::new_unchecked(0),
        HandlerEvent::MessageDropped(dropped),
    );

    let after_drop = gs.traffic().per_topic.get(&topics[0]).unwrap().tx;
    assert!(
        after_drop.data_bytes < after_publish.data_bytes,
        "a dropped publish should give its bytes back"
    );
    assert_eq!(after_drop.data_msgs, after_publish.data_msgs - 1);
}
