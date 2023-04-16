use std::collections::hash_map::DefaultHasher;
use std::fmt::format;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::utils::ip_util::get_public_ip;
use chrono::{DateTime, Utc};
use futures::{future::Either, prelude::*, select};
use libp2p::core::transport::Boxed;
use libp2p::gossipsub::{Behaviour, Event, Gossipsub, GossipsubEvent};
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::OrTransport, upgrade},
    gossipsub, identity, mdns, noise,
    swarm::NetworkBehaviour,
    swarm::{SwarmBuilder, SwarmEvent},
    tcp, yamux, PeerId, Swarm, Transport,
};
use libp2p_quic as quic;
use log::error;
use serde::{Deserialize, Serialize};
use tracing::info;

// We create a custom network behaviour that combines Gossipsub and Mdns.
#[derive(NetworkBehaviour)]
pub struct MyBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::async_io::Behaviour,
}

#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct MyMessage {
    pub pub_key: String,
    pub addr: String,
    pub enr: String,
    pub desc: String,
    pub timestamp_nanos_utc: i64,
    pub timestamp_nanos_local: i64,
}

pub fn gossipsub_listen(
    local_peer_id: PeerId,
    transport: Boxed<(PeerId, StreamMuxerBox)>,
    gossipsub: Behaviour,
    udp_port: String,
) -> Swarm<MyBehaviour> {
    // Create a Swarm to manage peers and events
    let mut swarm = {
        let mdns = mdns::async_io::Behaviour::new(mdns::Config::default(), local_peer_id)
            .expect("mdns error");
        let behaviour = MyBehaviour { gossipsub, mdns };
        SwarmBuilder::with_async_std_executor(transport, behaviour, local_peer_id).build()
    };

    // Listen on all interfaces and whatever port the OS assigns
    let curr_pub_ip = get_public_ip();
    if let Err(e) = swarm.listen_on(
        format!("/ip4/{}/udp/{}/quic-v1", curr_pub_ip, udp_port)
            .parse()
            .unwrap(),
    ) {
        error!("quic-v1,curr_pub_ip:{curr_pub_ip:?}, udp_port:{udp_port:?},err:{e:?}");
        swarm.listen_on(
            format!("/ip4/0.0.0.0/udp/{}/quic-v1", udp_port)
                .parse()
                .unwrap(),
        );
    }

    if let Err(e) = swarm.listen_on(
        format!("/ip4/{}/tcp/{}", curr_pub_ip, udp_port)
            .parse()
            .unwrap(),
    ) {
        error!("curr_pub_ip:{curr_pub_ip:?}, udp_port:{udp_port:?},err:{e:?}");
        swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", udp_port).parse().unwrap());
    }

    info!("pub/sub messages and they will be sent to connected peers using Gossipsub");
    swarm
}

pub fn init_gossipsub() -> (PeerId, Boxed<(PeerId, StreamMuxerBox)>, Behaviour) {
    // Create a random PeerId
    let id_keys = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(id_keys.public());
    info!("Local peer id: {local_peer_id}");

    // Set up an encrypted DNS-enabled TCP Transport over the Mplex protocol.
    let tcp_transport = tcp::async_io::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(
            noise::NoiseAuthenticated::xx(&id_keys).expect("signing libp2p-noise static keypair"),
        )
        .multiplex(yamux::YamuxConfig::default())
        .timeout(std::time::Duration::from_secs(20))
        .boxed();
    let quic_transport = quic::async_std::Transport::new(quic::Config::new(&id_keys));
    let transport = OrTransport::new(quic_transport, tcp_transport)
        .map(|either_output, _| match either_output {
            Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
        })
        .boxed();

    // To content-address message, we can take the hash of message and use it as an ID.
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    // Set a custom gossipsub configuration
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
        .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
        .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
        .build()
        .expect("Valid config");

    // build a gossipsub network behaviour
    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(id_keys),
        gossipsub_config,
    )
    .expect("Correct configuration");
    (local_peer_id, transport, gossipsub)
}

/// tracing_test https://docs.rs/tracing-test/latest/tracing_test/
/// https://stackoverflow.com/questions/72884779/how-to-print-tracing-output-in-tests
#[cfg(test)]
mod tests {
    use chrono::Local;
    use tracing::debug;
    use tracing_test::traced_test;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[traced_test]
    #[test]
    fn test() {
        let mut now = Utc::now();
        println!("{},{}", now, now.timestamp_nanos());
        let local_now = Local::now();
        println!("{},{}", now, now.timestamp_nanos());
    }
}
