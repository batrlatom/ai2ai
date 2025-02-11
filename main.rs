// Standard imports and CLI definitions.
use clap::{Parser, Subcommand};
use env_logger;

/// We use a current-thread Tokio runtime and a LocalSet so that non-Send types (like ZeroMQ sockets)
// can be used with spawn_local.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let cli = Cli::parse();
            match &cli.command {
                Some(Commands::Node(args)) => {
                    node::run_node(args.clone()).await;
                }
                Some(Commands::Cluster(args)) => {
                    test_runner::run_cluster(args.clone()).await;
                }
                None => {
                    println!("No subcommand provided. Use 'node' or 'cluster'.");
                }
            }
        })
        .await;
}

// ===== CLI Types =====
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a single node
    Node(node::NodeArgs),
    /// Deploy a cluster (test runner)
    Cluster(test_runner::ClusterArgs),
}

// ===== Module: block =====
mod block {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub struct Block {
        pub view: i64,
        // Use #[serde(default)] so that older blocks without this field will default to an empty Vec.
        #[serde(default)]
        pub transactions: Vec<String>,
        pub qc: Option<Vec<String>>,
        pub timestamp: f64,
        pub signature: Option<String>,
        pub prev_hash: Option<String>,
    }
}

// ===== Module: persistence_manager =====
mod persistence_manager {
    use rusqlite::{params, Connection};
    use std::sync::{Arc, Mutex};
    use log::info;
    use serde_json;
    use crate::block::Block;

    pub struct PersistenceManager {
        pub _db_path: String,
        pub conn: Arc<Mutex<Connection>>,
    }

    impl PersistenceManager {
        pub fn new(db_path: String) -> Self {
            let conn = Connection::open(&db_path).expect("Failed to open database");
            let pm = PersistenceManager {
                _db_path: db_path,
                conn: Arc::new(Mutex::new(conn)),
            };
            pm.create_tables();
            pm
        }

        pub fn create_tables(&self) {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "CREATE TABLE IF NOT EXISTS blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_data TEXT NOT NULL
                )",
                [],
            )
            .expect("Failed to create tables");
            info!("[PersistenceManager] Tables created or verified.");
        }

        pub fn store_block(&self, block: &Block) {
            let conn = self.conn.lock().unwrap();
            let block_str = serde_json::to_string(block).unwrap();
            conn.execute("INSERT INTO blocks (block_data) VALUES (?1)", params![block_str])
                .unwrap();
            info!("[PersistenceManager] Block stored: {:?}", block);
        }

        pub fn load_chain(&self) -> Vec<Block> {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT block_data FROM blocks ORDER BY id").unwrap();
            let block_iter = stmt
                .query_map([], |row| {
                    let data: String = row.get(0)?;
                    let block: Block = serde_json::from_str(&data).unwrap();
                    Ok(block)
                })
                .unwrap();
            let mut chain = Vec::new();
            for block in block_iter {
                chain.push(block.unwrap());
            }
            chain
        }

        pub fn replace_chain(&self, new_chain: &[Block]) {
            let conn = self.conn.lock().unwrap();
            conn.execute("DELETE FROM blocks", []).unwrap();
            for block in new_chain {
                let block_str = serde_json::to_string(block).unwrap();
                conn.execute("INSERT INTO blocks (block_data) VALUES (?1)", params![block_str])
                    .unwrap();
            }
            info!("[PersistenceManager] Local chain replaced with new chain.");
        }
    }
}

// ===== Module: vrf =====
#[allow(dead_code)]
mod vrf {
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
    use ed25519_dalek::{Signer, Verifier};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::{Digest, Sha512};
    use std::convert::TryInto;

    /// A basic VRF structure using an Ed25519 signing key.
    pub struct VRF {
        signing_key: SigningKey,
    }

    impl VRF {
        pub fn new() -> Self {
            let mut csprng = OsRng;
            let mut seed = [0u8; 32];
            csprng.fill_bytes(&mut seed);
            let signing_key = SigningKey::from_bytes(&seed);
            Self { signing_key }
        }

        pub fn from_seed(seed: &[u8]) -> Self {
            let seed_arr: &[u8; 32] = seed.try_into().expect("Seed must be 32 bytes");
            let signing_key = SigningKey::from_bytes(seed_arr);
            Self { signing_key }
        }

        pub fn prove(&self, message: &[u8]) -> (Vec<u8>, Signature) {
            let signature: Signature = self.signing_key.sign(message);
            let mut hasher = Sha512::new();
            hasher.update(signature.to_bytes());
            let output = hasher.finalize();
            (output.to_vec(), signature)
        }

        pub fn verify(
            public_key: &VerifyingKey,
            message: &[u8],
            output: &[u8],
            proof: &Signature,
        ) -> bool {
            if public_key.verify(message, proof).is_ok() {
                let mut hasher = Sha512::new();
                hasher.update(proof.to_bytes());
                let expected_output = hasher.finalize();
                expected_output.as_slice() == output
            } else {
                false
            }
        }

        pub fn public_key(&self) -> VerifyingKey {
            self.signing_key.verifying_key()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_dalek::Signature;

        #[test]
        fn test_vrf_prove_and_verify() {
            let vrf = VRF::new();
            let message = b"Test message";
            let (output, proof) = vrf.prove(message);
            let public_key = vrf.public_key();
            assert!(VRF::verify(&public_key, message, &output, &proof));
        }

        #[test]
        fn test_vrf_invalid_signature() {
            let vrf = VRF::new();
            let message = b"Test message";
            let (output, proof) = vrf.prove(message);
            let public_key = vrf.public_key();
            let mut bad_signature_bytes = proof.to_bytes();
            bad_signature_bytes[0] ^= 0xFF;
            let bad_proof = Signature::from_bytes(&bad_signature_bytes);
            assert!(!VRF::verify(&public_key, message, &output, &bad_proof));
        }

        #[test]
        fn test_vrf_invalid_message() {
            let vrf = VRF::new();
            let message = b"Test message";
            let (output, proof) = vrf.prove(message);
            let public_key = vrf.public_key();
            let bad_message = b"Another message";
            assert!(!VRF::verify(&public_key, bad_message, &output, &proof));
        }

        #[test]
        fn test_vrf_determinism() {
            let vrf = VRF::new();
            let message = b"Deterministic message";
            let (output1, proof1) = vrf.prove(message);
            let (output2, proof2) = vrf.prove(message);
            assert_eq!(proof1.to_bytes(), proof2.to_bytes());
            assert_eq!(output1, output2);
        }

        #[test]
        fn test_different_keys_produce_different_outputs() {
            let message = b"Test message";
            let vrf1 = VRF::new();
            let vrf2 = VRF::new();
            let (output1, proof1) = vrf1.prove(message);
            let (output2, proof2) = vrf2.prove(message);
            assert_ne!(proof1.to_bytes(), proof2.to_bytes());
            assert_ne!(output1, output2);
        }
    }
}

// ===== Module: network_manager =====
mod network_manager {
    use async_zmq::{Dealer, Router, SinkExt};
    use futures::StreamExt;
    use log::{debug, error, info};
    use serde::{Deserialize, Serialize};
    use serde_json;
    use std::collections::HashMap;
    use tokio::sync::mpsc;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Message {
        #[serde(rename = "type")]
        pub msg_type: String,
        pub view: Option<i64>,
        pub data: Option<String>,
        pub leader: Option<String>,
        pub qc: Option<Vec<String>>,
        pub node_id: Option<String>,
        pub vote: Option<bool>,
        pub block: Option<crate::block::Block>,
        pub chain: Option<Vec<crate::block::Block>>,
        pub signature: Option<String>,
    }

    pub type MessageItem = (String, Message);

    pub struct NetworkManager {
        pub node_id: String,
        pub _zmq_port: u16,
        pub _peer_endpoints: HashMap<String, String>,
        pub message_tx: mpsc::Sender<MessageItem>,
        pub message_rx: Rc<RefCell<mpsc::Receiver<MessageItem>>>,
        pub state_request_callback: Option<Rc<dyn Fn(String, Message) -> Box<dyn futures::Future<Output = ()> + 'static + Unpin>>>,
        pub client_sockets: RefCell<HashMap<String, Dealer<std::vec::IntoIter<Vec<u8>>, Vec<u8>>>>,
    }

    impl NetworkManager {
        pub async fn new(node_id: String, zmq_port: u16, peer_endpoints: HashMap<String, String>) -> Rc<Self> {
            let (tx, rx) = mpsc::channel(100);
            let rx = Rc::new(RefCell::new(rx));
            let bind_addr = format!("tcp://*:{}", zmq_port);
            let router_builder = async_zmq::router(&bind_addr)
                .expect("Failed to create router socket builder");
            let server_socket: Router<std::vec::IntoIter<Vec<u8>>, Vec<u8>> =
                router_builder.bind().expect("Failed to bind server socket");

            let mut sockets = HashMap::new();
            for (peer, endpoint) in &peer_endpoints {
                if peer == &node_id {
                    continue;
                }
                let dealer_builder = async_zmq::dealer(&endpoint)
                    .expect("Failed to create dealer socket builder");
                let dealer: Dealer<std::vec::IntoIter<Vec<u8>>, Vec<u8>> =
                    dealer_builder.connect().expect("Failed to connect dealer socket");
                sockets.insert(peer.clone(), dealer);
                info!("[NetworkManager {}] Client socket connected to {} at {}", node_id, peer, endpoint);
            }

            let nm = Rc::new(NetworkManager {
                node_id: node_id.clone(),
                _zmq_port: zmq_port,
                _peer_endpoints: peer_endpoints,
                message_tx: tx,
                message_rx: rx,
                state_request_callback: None,
                client_sockets: RefCell::new(sockets),
            });

            nm.start_receive_loop(server_socket);
            nm
        }

        fn start_receive_loop(&self, mut server_socket: Router<std::vec::IntoIter<Vec<u8>>, Vec<u8>>) {
            let tx = self.message_tx.clone();
            let node_id = self.node_id.clone();
            let state_request_callback = self.state_request_callback.clone();
            tokio::task::spawn_local(async move {
                while let Some(Ok(msg_parts)) = server_socket.next().await {
                    if msg_parts.len() < 2 {
                        error!("[NetworkManager {}] Incomplete message: {:?}", node_id, msg_parts);
                        continue;
                    }
                    let sender = String::from_utf8_lossy(&msg_parts[0]).to_string();
                    let msg_str = String::from_utf8_lossy(&msg_parts[msg_parts.len()-1]).to_string();
                    let payload: Message = serde_json::from_str(&msg_str).unwrap_or_else(|e| {
                        error!("[NetworkManager {}] JSON decode error: {}: {}", node_id, e, msg_str);
                        Message {
                            msg_type: "invalid".to_string(),
                            view: None,
                            data: None,
                            leader: None,
                            qc: None,
                            node_id: None,
                            vote: None,
                            block: None,
                            chain: None,
                            signature: None,
                        }
                    });
                    if payload.msg_type == "state_request" {
                        if let Some(callback) = &state_request_callback {
                            let fut = callback(sender.clone(), payload.clone());
                            tokio::task::spawn_local(Box::pin(fut));
                        } else {
                            info!("[NetworkManager {}] Enqueuing state_request message from {}: {:?}", node_id, sender, payload);
                            let _ = tx.send((sender, payload)).await;
                        }
                    } else {
                        info!("[NetworkManager {}] Enqueuing message from {}: {:?}", node_id, sender, payload);
                        let _ = tx.send((sender, payload)).await;
                    }
                }
            });
        }

        pub async fn send_message(&self, target: &str, message: &Message, signature: Option<String>) {
            let mut payload = message.clone();
            payload.signature = signature.or(Some(String::new()));
            let msg_str = serde_json::to_string(&payload).unwrap();
            let mut sockets = self.client_sockets.borrow_mut();
            if let Some(dealer) = sockets.get_mut(target) {
                let multipart = vec![b"".to_vec(), msg_str.clone().into_bytes()].into();
                let _ = dealer.send(multipart).await;
                debug!("[NetworkManager {}] Sent message to {}: {}", self.node_id, target, msg_str);
            } else {
                error!("[NetworkManager {}] No client socket for target {}", self.node_id, target);
            }
        }

        pub async fn broadcast_message(&self, message: &Message, exclude: Option<&Vec<String>>) {
            let default_exclude: Vec<String> = vec![];
            let exclude_set = exclude.unwrap_or(&default_exclude);
            let msg_str = serde_json::to_string(&message).unwrap();
            let mut sockets = self.client_sockets.borrow_mut();
            for (peer, dealer) in sockets.iter_mut() {
                if !exclude_set.contains(peer) {
                    let multipart = vec![b"".to_vec(), msg_str.clone().into_bytes()].into();
                    let _ = dealer.send(multipart).await;
                    debug!("[NetworkManager {}] Broadcasted message to {}: {:?}", self.node_id, peer, message);
                }
            }
        }

        pub fn update_peers(&self, new_peers: std::collections::HashMap<String, String>) {
            let mut sockets = self.client_sockets.borrow_mut();
            for (peer, endpoint) in new_peers {
                if !sockets.contains_key(&peer) && peer != self.node_id {
                    if let Ok(dealer_builder) = async_zmq::dealer(&endpoint) {
                        if let Ok(dealer) = dealer_builder.connect() {
                            sockets.insert(peer.clone(), dealer);
                            log::info!("[NetworkManager {}] Added dynamic peer {} at {}", self.node_id, peer, endpoint);
                        }
                    }
                }
            }
        }
    }
}

// ===== Module: hotstuff_core =====
mod hotstuff_core {
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::time;
    use log::{debug, error, info, trace, warn};
    use crate::network_manager::{NetworkManager, Message};
    use crate::persistence_manager::PersistenceManager;
    use crate::block::Block;
    use crate::vrf;
    use std::rc::Rc;
    use std::cell::RefCell;
    use rand::Rng;
    use sha2::Digest;

    pub struct Stats {
        pub block_count: u64,
        pub tx_count: u64,
    }

    pub struct HotStuffCore {
        pub node_id: String,
        pub network_manager: Rc<NetworkManager>,
        pub persistence: Rc<PersistenceManager>,
        pub pacemaker_timeout: Duration,
        pub peers: Vec<String>,
        pub vrf_keys: HashMap<String, Vec<u8>>,
        pub chain: Vec<Block>,
        pub current_view: i64,
        pub stats: Rc<RefCell<Stats>>,
    }

    impl HotStuffCore {
        pub fn new(
            node_id: String,
            network_manager: Rc<NetworkManager>,
            persistence: Rc<PersistenceManager>,
            pacemaker_timeout: Duration,
            peers: Vec<String>,
            vrf_keys: HashMap<String, Vec<u8>>,
        ) -> Self {
            let mut peers = peers;
            peers.sort();
            if !peers.contains(&node_id) {
                peers.push(node_id.clone());
                peers.sort();
            }
            let chain = persistence.load_chain();
            let current_view = if !chain.is_empty() {
                chain.iter().map(|b| b.view).max().unwrap() + 1
            } else {
                0
            };
            info!("Node {}: Loaded chain with {} blocks; starting at view {}", node_id, chain.len(), current_view);
            HotStuffCore {
                node_id,
                network_manager,
                persistence,
                pacemaker_timeout,
                peers,
                vrf_keys,
                chain,
                current_view,
                stats: Rc::new(RefCell::new(Stats { block_count: 0, tx_count: 0 })),
            }
        }

        pub fn finalize_block(&mut self, block: &Block) {
            let last_view = self.chain.last().map(|b| b.view).unwrap_or(-1);
            if block.view > last_view {
                self.persistence.store_block(block);
                self.chain.push(block.clone());
                info!("[Node {}] Finalized block for view {}", self.node_id, block.view);
                {
                    let mut stats = self.stats.borrow_mut();
                    stats.block_count += 1;
                    stats.tx_count += block.transactions.len() as u64;
                }
            } else {
                info!("[Node {}] Received stale block for view {} (last view: {})", self.node_id, block.view, last_view);
            }
        }

        pub async fn start(&mut self) {
            self.catchup().await;
            info!("[Node {}] Starting HotStuff consensus protocol at view {}", self.node_id, self.current_view);
            let stats = self.stats.clone();
            tokio::task::spawn_local(async move {
                loop {
                    time::sleep(Duration::from_secs(1)).await;
                    let mut s = stats.borrow_mut();
                    println!("Stats: {} blocks/s, {} tx/s", s.block_count, s.tx_count);
                    s.block_count = 0;
                    s.tx_count = 0;
                }
            });
            loop {
                self.run_consensus_round().await;
            }
        }

        pub async fn run_consensus_round(&mut self) {
            let view = self.current_view;
            let leader = self.determine_leader(view);
            info!("[Consensus] Node {} view {}: Leader is {}", self.node_id, view, leader);

            if self.node_id == leader {
                info!("[Consensus] Node {} is leader for view {}", self.node_id, view);
                let num_tx = rand::thread_rng().gen_range(1..=50);
                let mut transactions = Vec::new();
                for i in 0..num_tx {
                    transactions.push(format!("tx {} at view {}", i, view));
                }
                let proposal = Message {
                    msg_type: "proposal".to_string(),
                    view: Some(view),
                    data: Some(format!("Proposal with {} txs", num_tx)),
                    leader: Some(self.node_id.clone()),
                    qc: None,
                    node_id: None,
                    vote: None,
                    block: None,
                    chain: None,
                    signature: None,
                };
                info!("[Consensus] Leader {} broadcasting proposal: {:?}", self.node_id, proposal);
                self.network_manager.broadcast_message(&proposal, Some(&vec![self.node_id.clone()])).await;

                let votes = self.collect_messages("vote", view, self.pacemaker_timeout * 2).await;
                info!("[Consensus] Node {} received {} votes", self.node_id, votes.len());
                if self.has_quorum(&votes) {
                    let qc = self.aggregate_votes(&votes);
                    let commit_message = Message {
                        msg_type: "commit".to_string(),
                        view: Some(view),
                        qc: Some(qc.clone()),
                        leader: Some(self.node_id.clone()),
                        data: None,
                        node_id: None,
                        vote: None,
                        block: None,
                        chain: None,
                        signature: None,
                    };
                    info!("[Consensus] Leader {} broadcasting commit: {:?}", self.node_id, commit_message);
                    self.network_manager.broadcast_message(&commit_message, Some(&vec![self.node_id.clone()])).await;
                    let commit_acks = self.collect_messages("commit_ack", view, self.pacemaker_timeout * 2).await;
                    info!("[Consensus] Leader {} received {} commit acks", self.node_id, commit_acks.len());
                    if self.has_quorum(&commit_acks) {
                        let decide = Message {
                            msg_type: "decide".to_string(),
                            view: Some(view),
                            block: Some(Block {
                                view,
                                transactions: transactions.clone(),
                                qc: Some(qc.clone()),
                                timestamp: current_timestamp(),
                                signature: None,
                                prev_hash: None,
                            }),
                            leader: Some(self.node_id.clone()),
                            data: None,
                            qc: None,
                            node_id: None,
                            vote: None,
                            chain: None,
                            signature: None,
                        };
                        info!("[Consensus] Leader {} broadcasting decide: {:?}", self.node_id, decide);
                        self.network_manager.broadcast_message(&decide, Some(&vec![self.node_id.clone()])).await;
                        if let Some(block) = decide.block.clone() {
                            self.finalize_block(&block);
                        }
                    } else {
                        warn!("[Consensus] Leader {}: Insufficient commit acks in view {}", self.node_id, view);
                        self.handle_view_change().await;
                        return;
                    }
                } else {
                    warn!("[Consensus] Leader {}: Insufficient votes in view {}", self.node_id, view);
                    self.handle_view_change().await;
                    return;
                }
            } else {
                info!("[Consensus] Node {} is a replica in view {}", self.node_id, view);
                let proposal_opt = self.wait_for_message("proposal", view, self.pacemaker_timeout * 2).await;
                if proposal_opt.is_none() {
                    warn!("[Consensus] Node {}: Timeout waiting for proposal in view {}", self.node_id, view);
                    self.handle_view_change().await;
                    return;
                }
                let proposal = proposal_opt.unwrap();
                info!("[Consensus] Node {} received proposal: {:?}", self.node_id, proposal);
                if proposal.leader.as_deref() != Some(&leader) {
                    warn!("[Consensus] Node {}: Received proposal from {:?} but expected leader {}", self.node_id, proposal.leader, leader);
                    self.handle_view_change().await;
                    return;
                }
                let vote = Message {
                    msg_type: "vote".to_string(),
                    view: Some(view),
                    node_id: Some(self.node_id.clone()),
                    vote: Some(true),
                    data: None,
                    leader: None,
                    qc: None,
                    block: None,
                    chain: None,
                    signature: None,
                };
                info!("[Consensus] Node {} sending vote to leader {}", self.node_id, leader);
                self.network_manager.send_message(&leader, &vote, None).await;
                let commit_opt = self.wait_for_message("commit", view, self.pacemaker_timeout * 2).await;
                if commit_opt.is_none() {
                    warn!("[Consensus] Node {}: Timeout waiting for commit in view {}", self.node_id, view);
                    self.handle_view_change().await;
                    return;
                }
                let _commit = commit_opt.unwrap();
                let commit_ack = Message {
                    msg_type: "commit_ack".to_string(),
                    view: Some(view),
                    node_id: Some(self.node_id.clone()),
                    data: None,
                    leader: None,
                    qc: None,
                    vote: None,
                    block: None,
                    chain: None,
                    signature: None,
                };
                info!("[Consensus] Node {} sending commit_ack to leader {}", self.node_id, leader);
                self.network_manager.send_message(&leader, &commit_ack, None).await;
                let decide_opt = self.wait_for_message("decide", view, self.pacemaker_timeout * 2).await;
                if decide_opt.is_none() {
                    warn!("[Consensus] Node {}: Timeout waiting for decide in view {}", self.node_id, view);
                    self.handle_view_change().await;
                    return;
                }
                let decide = decide_opt.unwrap();
                info!("[Consensus] Node {} received decide message: {:?}", self.node_id, decide);
                if let Some(block) = decide.block.clone() {
                    self.finalize_block(&block);
                }
            }
            self.current_view += 1;
        }

        pub async fn wait_for_message(&self, msg_type: &str, view: i64, timeout_duration: Duration) -> Option<Message> {
            let expected_leader = self.determine_leader(view);
            let start = std::time::Instant::now();
            loop {
                if start.elapsed() > timeout_duration {
                    warn!("[HotStuffCore {}] Timeout waiting for message type '{}' in view {}", self.node_id, msg_type, view);
                    return None;
                }
                let mut rx = self.network_manager.message_rx.borrow_mut();
                if let Some((_sender, message)) = rx.recv().await {
                    if let Some(msg_view) = message.view {
                        if msg_view != view {
                            debug!("[HotStuffCore {}] Discarding out-of-view message: {:?}", self.node_id, message);
                            continue;
                        }
                    }
                    info!("[HotStuffCore {}] Dequeued message: {:?}", self.node_id, message);
                    if message.msg_type == msg_type {
                        if msg_type == "proposal" && message.leader.as_deref() != Some(&expected_leader) {
                            warn!("[HotStuffCore {}] Received proposal from {:?} but expected {}", self.node_id, message.leader, expected_leader);
                            continue;
                        }
                        return Some(message);
                    } else {
                        debug!("[HotStuffCore {}] Message does not match criteria: {:?}", self.node_id, message);
                    }
                } else {
                    time::sleep(Duration::from_millis(10)).await;
                }
            }
        }

        pub async fn collect_messages(&self, msg_type: &str, view: i64, max_wait: Duration) -> Vec<Message> {
            let mut messages = Vec::new();
            let start = std::time::Instant::now();
            loop {
                if start.elapsed() > max_wait {
                    break;
                }
                let mut rx = self.network_manager.message_rx.borrow_mut();
                if let Ok((_sender, message)) = rx.try_recv() {
                    if let Some(m_view) = message.view {
                        if m_view == view && message.msg_type == msg_type {
                            messages.push(message);
                        } else {
                            debug!("[HotStuffCore {}] Discarding non-matching message: {:?}", self.node_id, message);
                        }
                    }
                } else {
                    drop(rx);
                    time::sleep(Duration::from_millis(10)).await;
                }
            }
            messages
        }

        pub fn has_quorum(&self, messages: &[Message]) -> bool {
            messages.len() >= ((self.peers.len() / 2) + 1)
        }

        pub fn aggregate_votes(&self, votes: &[Message]) -> Vec<String> {
            votes.iter().filter_map(|v| v.node_id.clone()).collect()
        }

        pub async fn handle_view_change(&mut self) {
            info!("[HotStuffCore {}] Handling view change for view {}", self.node_id, self.current_view);
            self.current_view += 1;
            time::sleep(Duration::from_millis(10)).await;
        }

        pub fn calculate_block_hash(&self, block: &Block) -> String {
            let mut block_clone = block.clone();
            block_clone.signature = None;
            let serialized = serde_json::to_string(&block_clone).unwrap();
            let hash = sha2::Sha256::digest(serialized.as_bytes());
            format!("{:x}", hash)
        }

        pub fn verify_block_signature(&self, block: &Block) -> bool {
            if let Some(sig) = &block.signature {
                !sig.trim().is_empty()
            } else {
                false
            }
        }

        pub fn is_valid_chain(&self, chain: &[Block]) -> bool {
            if chain.is_empty() {
                return false;
            }
            let mut last_view = -1;
            for (i, block) in chain.iter().enumerate() {
                if block.view <= last_view {
                    return false;
                }
                last_view = block.view;
                if !self.verify_block_signature(block) {
                    return false;
                }
                if i > 0 {
                    let expected_prev_hash = self.calculate_block_hash(&chain[i - 1]);
                    if let Some(prev_hash) = &block.prev_hash {
                        if prev_hash != &expected_prev_hash {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
            true
        }

        pub async fn catchup(&mut self) {
            let request = Message {
                msg_type: "state_request".to_string(),
                view: None,
                data: None,
                leader: None,
                qc: None,
                node_id: Some(self.node_id.clone()),
                vote: None,
                block: None,
                chain: None,
                signature: None,
            };
            info!("[HotStuffCore {}] Broadcasting state_request for catch-up", self.node_id);
            self.network_manager.broadcast_message(&request, Some(&vec![self.node_id.clone()])).await;
            let mut responses: Vec<Vec<Block>> = Vec::new();
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(3) {
                let mut rx = self.network_manager.message_rx.borrow_mut();
                if let Ok((_sender, msg)) = rx.try_recv() {
                    if msg.msg_type == "state_response" {
                        if let Some(chain) = msg.chain {
                            responses.push(chain);
                        }
                    }
                }
                drop(rx);
                time::sleep(Duration::from_millis(10)).await;
            }
            let local_chain = if self.is_valid_chain(&self.chain) {
                self.chain.clone()
            } else {
                warn!("[HotStuffCore {}] Local chain is invalid. Will adopt a valid chain from peers if available.", self.node_id);
                Vec::new()
            };
            let mut longest = local_chain.clone();
            for chain in responses {
                if self.is_valid_chain(&chain) && chain.len() > longest.len() {
                    longest = chain;
                }
            }
            if longest.is_empty() {
                warn!("[HotStuffCore {}] No valid chain available from peers. Starting with an empty chain.", self.node_id);
                self.chain = Vec::new();
                self.current_view = 0;
            } else {
                if longest != self.chain {
                    self.persistence.replace_chain(&longest);
                    self.chain = longest;
                }
                self.current_view = self.chain.iter().map(|b| b.view).max().unwrap() + 1;
                info!("[HotStuffCore {}] Caught up to view {} via catchup", self.node_id, self.current_view);
            }
        }

        pub fn determine_leader(&self, view: i64) -> String {
            let mut best_peer: Option<String> = None;
            let mut best_value: Option<u128> = None;
            for peer in &self.peers {
                let alpha = format!("{}-{}", peer, view).into_bytes();
                let seed_opt = self.vrf_keys.get(peer);
                if seed_opt.is_none() {
                    error!("[HotStuffCore {}] No VRF key for peer {}", self.node_id, peer);
                    continue;
                }
                let seed = seed_opt.unwrap();
                if seed.len() != 32 {
                    error!("[HotStuffCore {}] Invalid VRF seed length for peer {}", self.node_id, peer);
                    continue;
                }
                let seed_arr: &[u8; 32] = seed.as_slice().try_into().expect("Seed length verified to be 32");
                let vrf_instance = vrf::VRF::from_seed(seed_arr);
                let (output, _proof) = vrf_instance.prove(&alpha);
                let mut arr = [0u8; 16];
                let slice = &output[..output.len().min(16)];
                arr[..slice.len()].copy_from_slice(slice);
                let score = u128::from_be_bytes(arr);
                trace!("[Leader Selection] Peer {} view {}: score = {}", peer, view, score);
                if best_value.is_none() || score < best_value.unwrap() {
                    best_value = Some(score);
                    best_peer = Some(peer.clone());
                }
            }
            let leader = best_peer.unwrap_or_default();
            info!("[Leader Selection] For view {}, selected leader: {}", view, leader);
            leader
        }
    }

    fn current_timestamp() -> f64 {
        let start = SystemTime::now();
        let since_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        since_epoch.as_secs_f64()
    }
}

// ===== Module: discovery =====
mod discovery {
    use kademlia_dht::{Key, Node as DHTNode, NodeData};
    use sha3::{Digest, Sha3_256};
    use log::trace;

    pub struct PeerDiscovery {
        dht_node: DHTNode,
    }

    impl PeerDiscovery {
        /// Initializes the DHT node on a given bind IP and port.
        /// Optionally, a bootstrap node can be provided as (ip, port).
        /// Each node binds to its unique discovery port.
        pub fn new(bind_ip: &str, bind_port: &str, bootstrap: Option<(&str, &str)>) -> Self {
            let bootstrap_data = bootstrap.map(|(ip, port)| {
                let addr = format!("{}:{}", ip, port);
                let mut hasher = Sha3_256::new();
                hasher.update(addr.as_bytes());
                let id = Key(hasher.finalize().into());
                trace!("Bootstrap node: addr = {}, id = {:?}", addr, id);
                NodeData { addr, id }
            });
            let dht_node = DHTNode::new(bind_ip, bind_port, bootstrap_data);
            trace!("Created DHT node on {}:{}", bind_ip, bind_port);
            PeerDiscovery { dht_node }
        }

        /// Publish this node’s endpoint under a key derived from its node ID.
        pub fn publish(&mut self, node_id: &str, endpoint: &str) {
            let key = Self::compute_key(node_id);
            trace!("Publishing node {}: endpoint = {}, key = {:?}", node_id, endpoint, key);
            self.dht_node.insert(key, endpoint);
        }

        /// Lookup a peer’s endpoint using its node ID.
        pub fn lookup(&mut self, node_id: &str) -> Option<String> {
            let key = Self::compute_key(node_id);
            let result = self.dht_node.get(&key);
            trace!("Looking up node {}: key = {:?}, found = {:?}", node_id, key, result);
            result
        }

        /// Computes a key from the given node ID.
        fn compute_key(node_id: &str) -> Key {
            let mut hasher = Sha3_256::new();
            hasher.update(node_id.as_bytes());
            Key(hasher.finalize().into())
        }
    }
}

// ===== Module: node =====
mod node {
    use clap::Parser;
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;
    use std::rc::Rc;
    use tokio::time::{sleep, Duration};
    use crate::hotstuff_core::HotStuffCore;
    use crate::network_manager::NetworkManager;
    use crate::persistence_manager::PersistenceManager;
    use crate::discovery::PeerDiscovery;
    use rand::Rng;
    use serde_json;
    use log::{info, debug};

    #[derive(Parser, Debug, Clone)]
    #[command(author, version, about)]
    pub struct NodeArgs {
        #[arg(long)]
        pub node_id: String,
        #[arg(long, default_value_t = 8000)]
        pub zmq_port: u16,
        #[arg(long, default_value_t = 5)]
        pub num_nodes: u16,
    }

    pub async fn run_node(args: NodeArgs) {
        // Compute a unique discovery port based on the ZMQ port.
        let discovery_port = (9000 + (args.zmq_port - 8000)).to_string();
        let bind_ip = "127.0.0.1";
        // For bootstrap, let node0 be the bootstrap. For other nodes, bootstrap from node0.
        let bootstrap = if args.node_id == "node0" { None } else { Some(("127.0.0.1", "9000")) };


        let mut peer_discovery = PeerDiscovery::new(bind_ip, &discovery_port, bootstrap);
        let zmq_endpoint = format!("tcp://localhost:{}", args.zmq_port);
        peer_discovery.publish(&args.node_id, &zmq_endpoint);
        info!("Node {} published its endpoint: {}", args.node_id, zmq_endpoint);

        // Wait for DHT propagation.
        sleep(Duration::from_secs(2)).await;

        // Build the list of expected peers.
        let expected_peers: Vec<String> = (0..args.num_nodes)
            .map(|i| format!("node{}", i))
            .collect();

        // Query the DHT for peer endpoints.
        let mut peer_endpoints = HashMap::new();
        for peer in &expected_peers {
            if peer == &args.node_id {
                continue;
            }
            if let Some(endpoint) = peer_discovery.lookup(peer) {
                peer_endpoints.insert(peer.clone(), endpoint);
            }
        }
        info!("Node {} discovered peers: {:?}", args.node_id, peer_endpoints);

        let db_file = format!("persistence_{}.db", args.node_id);
        let persistence = Rc::new(PersistenceManager::new(db_file));
        let network_manager = NetworkManager::new(args.node_id.clone(), args.zmq_port, peer_endpoints).await;

        // Clone node_id for use in the periodic update task.
        let node_id_clone = args.node_id.clone();
        let nm_clone = network_manager.clone();
        let expected_peers_clone = expected_peers.clone();
        // Wrap peer_discovery in a Tokio Mutex inside an Arc for Send safety.
        let pd_arc = std::sync::Arc::new(tokio::sync::Mutex::new(peer_discovery));
        {
            let pd_clone = pd_arc.clone();
            tokio::task::spawn_local(async move {
                loop {
                    let mut new_peers = HashMap::new();
                    {
                        let mut pd = pd_clone.lock().await;
                        for peer in &expected_peers_clone {
                            if peer == &node_id_clone {
                                continue;
                            }
                            if let Some(endpoint) = pd.lookup(peer) {
                                new_peers.insert(peer.clone(), endpoint);
                            }
                        }
                    }
                    debug!("Node {} updating peers: {:?}", node_id_clone, new_peers);
                    nm_clone.update_peers(new_peers);
                    sleep(Duration::from_secs(5)).await;
                }
            });
        }

        let hotstuff_peers = expected_peers.clone();
        let mut hotstuff = HotStuffCore::new(
            args.node_id.clone(),
            network_manager.clone(),
            persistence.clone(),
            Duration::from_millis(500),
            expected_peers,
            load_vrf_keys("vrf_keys.json", &hotstuff_peers),
        );
        if !persistence.load_chain().is_empty() {
            hotstuff.current_view = persistence.load_chain().iter().map(|b| b.view).max().unwrap() + 1;
        }
        sleep(Duration::from_secs(1)).await;
        tokio::task::spawn_local(async move {
            hotstuff.start().await;
        });
        loop {
            sleep(Duration::from_secs(1)).await;
        }
    }

    fn load_vrf_keys(filename: &str, nodes: &[String]) -> std::collections::HashMap<String, Vec<u8>> {
        let mut vrf_keys = std::collections::HashMap::new();
        if Path::new(filename).exists() {
            let data = fs::read_to_string(filename).expect("Failed to read vrf_keys file");
            let keys: std::collections::HashMap<String, String> =
                serde_json::from_str(&data).expect("Failed to parse vrf_keys");
            for (k, v) in keys {
                vrf_keys.insert(k, hex::decode(v).expect("Failed to decode hex"));
            }
        } else {
            for node in nodes {
                let key: [u8; 32] = rand::thread_rng().gen();
                vrf_keys.insert(node.clone(), key.to_vec());
            }
            let keys_hex: std::collections::HashMap<String, String> =
                vrf_keys.iter().map(|(k, v)| (k.clone(), hex::encode(v))).collect();
            fs::write(filename, serde_json::to_string_pretty(&keys_hex).unwrap())
                .expect("Failed to write vrf_keys file");
        }
        vrf_keys
    }
}

// ===== Module: test_runner =====
mod test_runner {
    use clap::Parser;
    use tokio::process::Command;
    use tokio::time::{sleep, Duration};
    use std::process::Stdio;
    use log::info;

    #[derive(Parser, Debug, Clone)]
    #[command(author, version, about)]
    pub struct ClusterArgs {
        #[arg(long)]
        pub nodes: u16,
        #[arg(long, default_value_t = 1)]
        pub bft: u16,
    }

    pub async fn run_cluster(args: ClusterArgs) {
        info!("[TestRunner] Deploying cluster with {} nodes (BFT threshold {})", args.nodes, args.bft);
    
        let mut processes = Vec::new();
    
        // --- Start node0 first ---
        {
            let zmq_port = 8000;
            let node_id = "node0".to_string();
    
            let child = Command::new("cargo")
                .args([
                    "run",
                    "--bin", "hotstuff",
                    "--",
                    "node",
                    "--node-id", &node_id,
                    "--zmq-port", &zmq_port.to_string(),
                    "--num-nodes", &args.nodes.to_string()
                ])
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to spawn node0 process");
    
            processes.push(child);
            info!("[TestRunner] Launched node0 on port {zmq_port}");
    
            // Give node0 time to start its DHT and bind on 127.0.0.1:9000
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    
        // --- Now launch the rest ---
        for i in 1..args.nodes {
            let zmq_port = 8000 + i;
            let node_id = format!("node{}", i);
    
            let child = Command::new("cargo")
                .args([
                    "run",
                    "--bin", "hotstuff",
                    "--",
                    "node",
                    "--node-id", &node_id,
                    "--zmq-port", &zmq_port.to_string(),
                    "--num-nodes", &args.nodes.to_string()
                ])
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("Failed to spawn node process");
    
            processes.push(child);
            info!("[TestRunner] Launched {} on port {}", node_id, zmq_port);
        }
    
        info!("[TestRunner] Cluster deployed. Press Ctrl+C to terminate.");
    
        // Keep the test-runner process alive:
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}
