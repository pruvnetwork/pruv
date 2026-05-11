//! P2P layer — real libp2p gossipsub swarm for peer discovery and signature sharing.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identify,
    identity::{self, Keypair},
    mdns,
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::config::NodeConfig;

// ─── Wire message types ───────────────────────────────────────────────────────

/// Heartbeat message broadcast to all gossip peers every 30 s.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HeartbeatMessage {
    /// Base58-encoded operator public key.
    pub operator_pubkey: String,
    /// Slot of the last attestation submitted (0 if none yet).
    pub last_attestation_slot: u64,
    /// Unix timestamp of this heartbeat (seconds).
    pub timestamp: u64,
    /// Node software semver.
    pub version: String,
}

/// A peer signature received over the gossip network.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeerSignature {
    pub program_id: [u8; 32],
    pub program_hash: [u8; 32],
    /// Ed25519 verifying key (32 bytes) of the signing node.
    pub signer: [u8; 32],
    /// Ed25519 signature (64 bytes) stored as Vec<u8> for serde compatibility.
    pub signature: Vec<u8>,
}

// ─── Network behaviour ────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct PruvBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns:      mdns::tokio::Behaviour,
    identify:  identify::Behaviour,
}

// ─── Topic constants ──────────────────────────────────────────────────────────

const TOPIC_SIGS:      &str = "pruv-attestation-sigs";
const TOPIC_HEARTBEAT: &str = "pruv-heartbeat";

// ─── Public API ───────────────────────────────────────────────────────────────

/// Shared slot counter updated by the attestor subsystem.
pub type LastSlot = Arc<std::sync::atomic::AtomicU64>;

/// Start the P2P gossip layer.
///
/// Returns:
/// - `JoinHandle` for the swarm task.
/// - `Receiver<PeerSignature>` — inbound signatures from remote peers.
/// - `Sender<PeerSignature>`   — publish outbound signatures to gossip.
/// - `LastSlot` — write the current attestation slot here so heartbeats
///   carry an accurate value.
pub async fn start(
    cfg: Arc<NodeConfig>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<(
    tokio::task::JoinHandle<()>,
    mpsc::Receiver<PeerSignature>,
    mpsc::Sender<PeerSignature>,
    LastSlot,
)> {
    // ── Build libp2p identity from operator Ed25519 keypair ──────────────────
    // libp2p ed25519::Keypair::try_from_bytes expects 64 bytes:
    // [0..32] = secret scalar, [32..64] = compressed pubkey — same layout as
    // ed25519-dalek, so we can pass the full operator_keypair_bytes directly.
    let mut kp_bytes = cfg.operator_keypair_bytes; // copy [u8; 64]
    let ed_kp = identity::ed25519::Keypair::try_from_bytes(&mut kp_bytes)
        .context("libp2p ed25519 key derivation failed")?;
    let local_keypair = Keypair::from(ed_kp);
    let local_peer_id  = PeerId::from(&local_keypair.public());
    info!("P2P local PeerId: {}", local_peer_id);

    // ── Channels ─────────────────────────────────────────────────────────────
    let (sig_tx, sig_rx)     = mpsc::channel::<PeerSignature>(256);
    let (pub_tx, mut pub_rx) = mpsc::channel::<PeerSignature>(256);
    let last_slot            = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let last_slot_clone      = Arc::clone(&last_slot);

    let listen_addr: Multiaddr = cfg.p2p_listen_addr
        .parse()
        .context("invalid P2P listen addr")?;
    let bootstrap_peers = cfg.bootstrap_peers.clone();
    let operator_pubkey = cfg.operator_pubkey().to_string();

    let handle = tokio::spawn(async move {
        // ── Build swarm ───────────────────────────────────────────────────
        let mut swarm = match build_swarm(local_keypair, local_peer_id) {
            Ok(s)  => s,
            Err(e) => { warn!("P2P swarm build failed: {}", e); return; }
        };

        // Listen
        if let Err(e) = swarm.listen_on(listen_addr.clone()) {
            warn!("P2P listen failed on {}: {}", listen_addr, e);
            return;
        }
        info!("P2P layer listening on {}", listen_addr);

        // Subscribe to topics
        let topic_sigs = IdentTopic::new(TOPIC_SIGS);
        let topic_hb   = IdentTopic::new(TOPIC_HEARTBEAT);
        swarm.behaviour_mut().gossipsub.subscribe(&topic_sigs).ok();
        swarm.behaviour_mut().gossipsub.subscribe(&topic_hb).ok();

        // Dial bootstrap peers
        for addr_str in &bootstrap_peers {
            match addr_str.parse::<Multiaddr>() {
                Ok(addr) => { swarm.dial(addr).ok(); }
                Err(e)   => warn!("P2P: bad bootstrap addr '{}': {}", addr_str, e),
            }
        }
        info!("P2P bootstrap peers: {:?}", bootstrap_peers);

        // ── Heartbeat ticker ──────────────────────────────────────────────
        let mut hb_interval = tokio::time::interval(Duration::from_secs(30));
        hb_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // ── Event loop ────────────────────────────────────────────────────
        loop {
            tokio::select! {
                event = swarm.next() => {
                    let Some(event) = event else { break };
                    handle_swarm_event(event, &sig_tx, &topic_sigs);
                }

                outbound = pub_rx.recv() => {
                    let Some(sig) = outbound else { break };
                    match serde_json::to_vec(&sig) {
                        Ok(payload) => {
                            if let Err(e) = swarm.behaviour_mut()
                                .gossipsub.publish(topic_sigs.clone(), payload)
                            {
                                debug!("P2P: publish sig error: {:?}", e);
                            } else {
                                metrics::counter!("pruv_p2p_sigs_published_total")
                                    .increment(1);
                            }
                        }
                        Err(e) => warn!("P2P: failed to serialise outbound sig: {}", e),
                    }
                }

                _ = hb_interval.tick() => {
                    let slot = last_slot_clone.load(std::sync::atomic::Ordering::Relaxed);

                    // ── Gossipsub mesh size ───────────────────────────────────
                    // Count unique peers subscribed to either topic; this is
                    // the most useful "live peer count" for operators.
                    let mesh_sigs = swarm.behaviour()
                        .gossipsub
                        .mesh_peers(&topic_sigs.hash())
                        .count() as f64;
                    let mesh_hb = swarm.behaviour()
                        .gossipsub
                        .mesh_peers(&topic_hb.hash())
                        .count() as f64;
                    let mesh_total = mesh_sigs.max(mesh_hb);
                    metrics::gauge!("pruv_p2p_gossip_mesh_size").set(mesh_total);
                    info!(
                        "P2P heartbeat tick — mesh peers: sigs={} hb={} connections={}",
                        mesh_sigs as usize,
                        mesh_hb as usize,
                        swarm.connected_peers().count()
                    );

                    let hb = HeartbeatMessage {
                        operator_pubkey: operator_pubkey.clone(),
                        last_attestation_slot: slot,
                        timestamp: unix_now(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    };
                    match serde_json::to_vec(&hb) {
                        Ok(payload) => {
                            if let Err(e) = swarm.behaviour_mut()
                                .gossipsub.publish(topic_hb.clone(), payload)
                            {
                                // No peers yet — not an error at startup.
                                debug!("P2P: heartbeat publish: {:?}", e);
                            }
                            metrics::counter!("pruv_p2p_heartbeats_total").increment(1);
                        }
                        Err(e) => warn!("P2P: heartbeat serialise error: {}", e),
                    }
                }

                _ = shutdown.recv() => {
                    info!("P2P layer shutting down.");
                    break;
                }
            }
        }
    });

    Ok((handle, sig_rx, pub_tx, last_slot))
}

// ─── Swarm builder ────────────────────────────────────────────────────────────

fn build_swarm(
    keypair: Keypair,
    _peer_id: PeerId,
) -> anyhow::Result<libp2p::Swarm<PruvBehaviour>> {
    let gossipsub_cfg = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(ValidationMode::Strict)
        .max_transmit_size(256 * 1024)  // 256 KB
        .build()
        .map_err(|e| anyhow::anyhow!("gossipsub config: {}", e))?;

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let gossipsub = gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(key.clone()),
                gossipsub_cfg,
            )
            .map_err(|e| anyhow::anyhow!("gossipsub init: {}", e))?;

            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                key.public().to_peer_id(),
            )?;

            let identify = identify::Behaviour::new(
                identify::Config::new("/pruv/1.0.0".into(), key.public()),
            );

            Ok(PruvBehaviour { gossipsub, mdns, identify })
        })?
        .with_swarm_config(|c| {
            c.with_idle_connection_timeout(Duration::from_secs(60))
        })
        .build();

    Ok(swarm)
}

// ─── Event handler ────────────────────────────────────────────────────────────

fn handle_swarm_event(
    event: SwarmEvent<PruvBehaviourEvent>,
    sig_tx: &mpsc::Sender<PeerSignature>,
    topic_sigs: &IdentTopic,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            info!("P2P listening on {}", address);
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            info!("P2P: connected to {}", peer_id);
            metrics::counter!("pruv_p2p_connections_total").increment(1);
            metrics::gauge!("pruv_p2p_peers_connected").increment(1.0);
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            debug!("P2P: disconnected from {} ({:?})", peer_id, cause);
            metrics::gauge!("pruv_p2p_peers_connected").decrement(1.0);
        }
        SwarmEvent::Behaviour(PruvBehaviourEvent::Mdns(
            mdns::Event::Discovered(peers)
        )) => {
            for (peer, addr) in peers {
                info!("P2P mDNS discovered {} at {}", peer, addr);
            }
        }
        SwarmEvent::Behaviour(PruvBehaviourEvent::Gossipsub(
            gossipsub::Event::Message { message, .. }
        )) => {
            if message.topic == topic_sigs.hash() {
                match serde_json::from_slice::<PeerSignature>(&message.data) {
                    Ok(sig) => {
                        debug!(
                            "P2P: received PeerSignature from {:?}",
                            message.source
                        );
                        metrics::counter!("pruv_p2p_sigs_received_total").increment(1);
                        if let Err(e) = sig_tx.try_send(sig) {
                            warn!(
                                "P2P: inbound PeerSignature dropped — channel full or closed \
                                 (buf=256): {}",
                                e
                            );
                            metrics::counter!("pruv_p2p_sigs_dropped_total").increment(1);
                        }
                    }
                    Err(e) => {
                        warn!("P2P: failed to deserialise PeerSignature: {}", e);
                    }
                }
            } else {
                // heartbeat topic or other
                match serde_json::from_slice::<HeartbeatMessage>(&message.data) {
                    Ok(hb) => {
                        info!(
                            "P2P ♥ heartbeat from {} | slot={} | v={} | ts={}",
                            hb.operator_pubkey,
                            hb.last_attestation_slot,
                            hb.version,
                            hb.timestamp,
                        );
                        metrics::counter!("pruv_p2p_heartbeats_received_total").increment(1);
                    }
                    Err(_) => {
                        debug!("P2P: unknown gossip message on topic {:?}", message.topic);
                    }
                }
            }
        }
        SwarmEvent::Behaviour(PruvBehaviourEvent::Gossipsub(
            gossipsub::Event::Subscribed { peer_id, topic }
        )) => {
            info!("P2P: {} subscribed to {}", peer_id, topic);
        }
        SwarmEvent::Behaviour(PruvBehaviourEvent::Identify(
            identify::Event::Received { peer_id, info }
        )) => {
            debug!("P2P identify: {} runs {}", peer_id, info.protocol_version);
        }
        _ => {}
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}