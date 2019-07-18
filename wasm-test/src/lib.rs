mod utils;

use lightning::chain::chaininterface;
use lightning::chain::keysinterface;
use lightning::chain::transaction::OutPoint;
use lightning::chain::keysinterface::KeysInterface;
use lightning::ln::channelmonitor;
use lightning::ln::channelmonitor::HTLCUpdate;
use lightning::ln::channelmanager::{ChannelManager, PaymentPreimage, PaymentHash};
use lightning::ln::router::{Route, Router};
use lightning::ln::msgs;
use lightning::ln::msgs::{ChannelMessageHandler,RoutingMessageHandler};
use lightning::util::events::{Event, EventsProvider, MessageSendEvent, MessageSendEventsProvider};
use lightning::util::logger::Logger;
use lightning::util::logger::Level;
use lightning::util::config::UserConfig;
use lightning::chain::chaininterface::ConfirmationTarget;
use lightning::util::logger::Record;

use bitcoin_hashes::sha256::Hash as Sha256;
use bitcoin_hashes::Hash;

use bitcoin::Transaction;
use bitcoin::Network;
use bitcoin::BlockHeader;
use bitcoin::Script;
use bitcoin::TxOut;
use bitcoin::util::hash::BitcoinHash;

use secp256k1::Secp256k1;
use secp256k1::SecretKey;

use std::cell::RefCell;
use std::default::Default;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread::sleep_ms;
use std::collections::HashSet;

pub struct TestLogger {
	level: Level,
	id: String,
}

impl TestLogger {
	pub fn new() -> TestLogger {
		Self::with_id("".to_owned())
	}
	pub fn with_id(id: String) -> TestLogger {
		TestLogger {
			level: Level::Trace,
			id,
		}
	}
	pub fn enable(&mut self, level: Level) {
		self.level = level;
	}
}

impl Logger for TestLogger {
	fn log(&self, record: &Record) {
		if self.level >= record.level {
			let a = format!("{:<5} {} [{} : {}, {}] {}", record.level.to_string(), self.id, record.module_path, record.file, record.line, record.args);
            alert(&a);
		}
	}
}

pub struct TestChannelMonitor {
	pub added_monitors: Mutex<Vec<(OutPoint, channelmonitor::ChannelMonitor)>>,
	pub simple_monitor: Arc<channelmonitor::SimpleManyChannelMonitor<OutPoint>>,
	pub update_ret: Mutex<Result<(), channelmonitor::ChannelMonitorUpdateErr>>,
}
impl TestChannelMonitor {
	pub fn new(chain_monitor: Arc<chaininterface::ChainWatchInterface>, broadcaster: Arc<chaininterface::BroadcasterInterface>, logger: Arc<Logger>, fee_estimator: Arc<chaininterface::FeeEstimator>) -> Self {
		Self {
			added_monitors: Mutex::new(Vec::new()),
			simple_monitor: channelmonitor::SimpleManyChannelMonitor::new(chain_monitor, broadcaster, logger, fee_estimator),
			update_ret: Mutex::new(Ok(())),
		}
	}
}
impl channelmonitor::ManyChannelMonitor for TestChannelMonitor {
	fn add_update_monitor(&self, funding_txo: OutPoint, monitor: channelmonitor::ChannelMonitor) -> Result<(), channelmonitor::ChannelMonitorUpdateErr> {
		self.simple_monitor.add_update_monitor(funding_txo, monitor)
	}

	fn fetch_pending_htlc_updated(&self) -> Vec<HTLCUpdate> {
		return self.simple_monitor.fetch_pending_htlc_updated();
	}
}

pub struct TestBroadcaster {
	pub txn_broadcasted: Mutex<Vec<Transaction>>,
}
impl chaininterface::BroadcasterInterface for TestBroadcaster {
	fn broadcast_transaction(&self, tx: &Transaction) {
		self.txn_broadcasted.lock().unwrap().push(tx.clone());
	}
}


pub struct Node {
	pub chain_monitor: Arc<chaininterface::ChainWatchInterfaceUtil>,
	pub tx_broadcaster: Arc<TestBroadcaster>,
	pub chan_monitor: Arc<TestChannelMonitor>,
	pub keys_manager: Arc<TestKeysInterface>,
	pub node: Arc<ChannelManager>,
	pub router: Router,
	pub node_seed: [u8; 32],
	pub network_payment_count: Rc<RefCell<u8>>,
	pub network_chan_count: Rc<RefCell<u32>>,
}
impl Drop for Node {
	fn drop(&mut self) {
		if !::std::thread::panicking() {
			// Check that we processed all pending events
			assert!(self.node.get_and_clear_pending_msg_events().is_empty());
			assert!(self.node.get_and_clear_pending_events().is_empty());
			assert!(self.chan_monitor.added_monitors.lock().unwrap().is_empty());
		}
	}
}

pub struct SendEvent {
	pub node_id: secp256k1::PublicKey,
	pub msgs: Vec<msgs::UpdateAddHTLC>,
	pub commitment_msg: msgs::CommitmentSigned,
}
impl SendEvent {
	pub fn from_commitment_update(node_id: secp256k1::PublicKey, updates: msgs::CommitmentUpdate) -> SendEvent {
		assert!(updates.update_fulfill_htlcs.is_empty());
		assert!(updates.update_fail_htlcs.is_empty());
		assert!(updates.update_fail_malformed_htlcs.is_empty());
		assert!(updates.update_fee.is_none());
		SendEvent { node_id: node_id, msgs: updates.update_add_htlcs, commitment_msg: updates.commitment_signed }
	}

	pub fn from_event(event: MessageSendEvent) -> SendEvent {
		match event {
			MessageSendEvent::UpdateHTLCs { node_id, updates } => SendEvent::from_commitment_update(node_id, updates),
			_ => panic!("Unexpected event type!"),
		}
	}

	pub fn from_node(node: &Node) -> SendEvent {
		let mut events = node.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.pop().unwrap())
	}
}

macro_rules! get_revoke_commit_msgs {
	($node: expr, $node_id: expr) => {
		{
			let events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 2);
			(match events[0] {
				MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
					assert_eq!(*node_id, $node_id);
					(*msg).clone()
				},
				_ => panic!("Unexpected event"),
			}, match events[1] {
				MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
					assert_eq!(*node_id, $node_id);
					assert!(updates.update_add_htlcs.is_empty());
					assert!(updates.update_fulfill_htlcs.is_empty());
					assert!(updates.update_fail_htlcs.is_empty());
					assert!(updates.update_fail_malformed_htlcs.is_empty());
					assert!(updates.update_fee.is_none());
					updates.commitment_signed.clone()
				},
				_ => panic!("Unexpected event"),
			})
		}
	}
}

macro_rules! check_added_monitors {
	($node: expr, $count: expr) => {
		{
			let mut added_monitors = $node.chan_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), $count);
			added_monitors.clear();
		}
	}
}

macro_rules! commitment_signed_dance {
	($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr, true /* skip last step */) => {
		{
			check_added_monitors!($node_a, 0);
			assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
			$node_a.node.handle_commitment_signed(&$node_b.node.get_our_node_id(), &$commitment_signed).unwrap();
			check_added_monitors!($node_a, 1);
			commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, false);
		}
	};
	($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, true /* return extra message */, true /* return last RAA */) => {
		{
			let (as_revoke_and_ack, as_commitment_signed) = get_revoke_commit_msgs!($node_a, $node_b.node.get_our_node_id());
			check_added_monitors!($node_b, 0);
			assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
			$node_b.node.handle_revoke_and_ack(&$node_a.node.get_our_node_id(), &as_revoke_and_ack).unwrap();
			assert!($node_b.node.get_and_clear_pending_msg_events().is_empty());
			check_added_monitors!($node_b, 1);
			$node_b.node.handle_commitment_signed(&$node_a.node.get_our_node_id(), &as_commitment_signed).unwrap();
			let (bs_revoke_and_ack, extra_msg_option) = {
				let events = $node_b.node.get_and_clear_pending_msg_events();
				assert!(events.len() <= 2);
				(match events[0] {
					MessageSendEvent::SendRevokeAndACK { ref node_id, ref msg } => {
						assert_eq!(*node_id, $node_a.node.get_our_node_id());
						(*msg).clone()
					},
					_ => panic!("Unexpected event"),
				}, events.get(1).map(|e| e.clone()))
			};
			check_added_monitors!($node_b, 1);
			if $fail_backwards {
				assert!($node_a.node.get_and_clear_pending_events().is_empty());
				assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
			}
			(extra_msg_option, bs_revoke_and_ack)
		}
	};
	($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr, true /* skip last step */, false /* return extra message */, true /* return last RAA */) => {
		{
			check_added_monitors!($node_a, 0);
			assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
			$node_a.node.handle_commitment_signed(&$node_b.node.get_our_node_id(), &$commitment_signed).unwrap();
			check_added_monitors!($node_a, 1);
			let (extra_msg_option, bs_revoke_and_ack) = commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true, true);
			assert!(extra_msg_option.is_none());
			bs_revoke_and_ack
		}
	};
	($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, true /* return extra message */) => {
		{
			let (extra_msg_option, bs_revoke_and_ack) = commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true, true);
			$node_a.node.handle_revoke_and_ack(&$node_b.node.get_our_node_id(), &bs_revoke_and_ack).unwrap();
			check_added_monitors!($node_a, 1);
			extra_msg_option
		}
	};
	($node_a: expr, $node_b: expr, (), $fail_backwards: expr, true /* skip last step */, false /* no extra message */) => {
		{
			assert!(commitment_signed_dance!($node_a, $node_b, (), $fail_backwards, true, true).is_none());
		}
	};
	($node_a: expr, $node_b: expr, $commitment_signed: expr, $fail_backwards: expr) => {
		{
			commitment_signed_dance!($node_a, $node_b, $commitment_signed, $fail_backwards, true);
			if $fail_backwards {
				expect_pending_htlcs_forwardable!($node_a);
				check_added_monitors!($node_a, 1);
			} else {
				assert!($node_a.node.get_and_clear_pending_msg_events().is_empty());
			}
		}
	}
}

macro_rules! get_payment_preimage_hash {
	($node: expr) => {
		{
			let payment_preimage = PaymentPreimage([*$node.network_payment_count.borrow(); 32]);
			*$node.network_payment_count.borrow_mut() += 1;
			let payment_hash = PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner());
			(payment_preimage, payment_hash)
		}
	}
}

macro_rules! expect_pending_htlcs_forwardable {
	($node: expr) => {{
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PendingHTLCsForwardable { time_forwardable } => {
				alert("Sleeping, cause we have to :(");
				sleep_ms(2000);
			},
			_ => panic!("Unexpected event"),
		};
		$node.node.process_pending_htlc_forwards();
	}}
}

macro_rules! expect_payment_received {
	($node: expr, $expected_payment_hash: expr, $expected_recv_value: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentReceived { ref payment_hash, amt } => {
				assert_eq!($expected_payment_hash, *payment_hash);
				assert_eq!($expected_recv_value, amt);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

macro_rules! expect_payment_sent {
	($node: expr, $expected_payment_preimage: expr) => {
		let events = $node.node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		match events[0] {
			Event::PaymentSent { ref payment_preimage } => {
				assert_eq!($expected_payment_preimage, *payment_preimage);
			},
			_ => panic!("Unexpected event"),
		}
	}
}

macro_rules! get_event_msg {
	($node: expr, $event_type: path, $node_id: expr) => {
		{
			let events = $node.node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			match events[0] {
				$event_type { ref node_id, ref msg } => {
					assert_eq!(*node_id, $node_id);
					(*msg).clone()
				},
				_ => panic!("Unexpected event"),
			}
		}
	}
}

pub struct TestKeysInterface {
	backing: keysinterface::KeysManager,
	pub override_session_priv: Mutex<Option<SecretKey>>,
	pub override_channel_id_priv: Mutex<Option<[u8; 32]>>,
}

impl keysinterface::KeysInterface for TestKeysInterface {
	fn get_node_secret(&self) -> SecretKey { self.backing.get_node_secret() }
	fn get_destination_script(&self) -> Script { self.backing.get_destination_script() }
	fn get_shutdown_pubkey(&self) -> secp256k1::PublicKey { self.backing.get_shutdown_pubkey() }
	fn get_channel_keys(&self, inbound: bool) -> keysinterface::ChannelKeys { self.backing.get_channel_keys(inbound) }

	fn get_session_key(&self) -> SecretKey {
		match *self.override_session_priv.lock().unwrap() {
			Some(key) => key.clone(),
			None => self.backing.get_session_key()
		}
	}

	fn get_channel_id(&self) -> [u8; 32] {
		match *self.override_channel_id_priv.lock().unwrap() {
			Some(key) => key.clone(),
			None => self.backing.get_channel_id()
		}
	}
}

impl TestKeysInterface {
	pub fn new(seed: &[u8; 32], network: Network, logger: Arc<Logger>) -> Self {
		Self {
			backing: keysinterface::KeysManager::new(seed, network, logger),
			override_session_priv: Mutex::new(None),
			override_channel_id_priv: Mutex::new(None),
		}
	}
}

pub struct TestFeeEstimator {
	pub sat_per_kw: u64,
}
impl chaininterface::FeeEstimator for TestFeeEstimator {
	fn get_est_sat_per_1000_weight(&self, _confirmation_target: ConfirmationTarget) -> u64 {
		self.sat_per_kw
	}
}

pub const CHAN_CONFIRM_DEPTH: u32 = 100;
pub fn confirm_transaction(chain: &chaininterface::ChainWatchInterfaceUtil, tx: &Transaction, chan_id: u32) {
	assert!(chain.does_match_tx(tx));
	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	chain.block_connected_checked(&header, 1, &[tx; 1], &[chan_id; 1]);
	for i in 2..CHAN_CONFIRM_DEPTH {
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		chain.block_connected_checked(&header, i, &[tx; 0], &[0; 0]);
	}
}

pub fn send_along_route_with_hash(origin_node: &Node, route: Route, expected_route: &[&Node], recv_value: u64, our_payment_hash: PaymentHash) {
	let mut payment_event = {
		origin_node.node.send_payment(route, our_payment_hash).unwrap();
		check_added_monitors!(origin_node, 1);

		let mut events = origin_node.node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 1);
		SendEvent::from_event(events.remove(0))
	};
	let mut prev_node = origin_node;

	for (idx, &node) in expected_route.iter().enumerate() {
		assert_eq!(node.node.get_our_node_id(), payment_event.node_id);

		node.node.handle_update_add_htlc(&prev_node.node.get_our_node_id(), &payment_event.msgs[0]).unwrap();
		check_added_monitors!(node, 0);
		commitment_signed_dance!(node, prev_node, payment_event.commitment_msg, false);

		expect_pending_htlcs_forwardable!(node);

		if idx == expected_route.len() - 1 {
			let events_2 = node.node.get_and_clear_pending_events();
			assert_eq!(events_2.len(), 1);
			match events_2[0] {
				Event::PaymentReceived { ref payment_hash, amt } => {
					assert_eq!(our_payment_hash, *payment_hash);
					assert_eq!(amt, recv_value);
				},
				_ => panic!("Unexpected event"),
			}
		} else {
			let mut events_2 = node.node.get_and_clear_pending_msg_events();
			assert_eq!(events_2.len(), 1);
			check_added_monitors!(node, 1);
			payment_event = SendEvent::from_event(events_2.remove(0));
			assert_eq!(payment_event.msgs.len(), 1);
		}

		prev_node = node;
	}
}

pub fn send_along_route(origin_node: &Node, route: Route, expected_route: &[&Node], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let (our_payment_preimage, our_payment_hash) = get_payment_preimage_hash!(origin_node);
	send_along_route_with_hash(origin_node, route, expected_route, recv_value, our_payment_hash);
	(our_payment_preimage, our_payment_hash)
}

pub fn claim_payment_along_route(origin_node: &Node, expected_route: &[&Node], skip_last: bool, our_payment_preimage: PaymentPreimage) {
	assert!(expected_route.last().unwrap().node.claim_funds(our_payment_preimage));
	check_added_monitors!(expected_route.last().unwrap(), 1);

	let mut next_msgs: Option<(msgs::UpdateFulfillHTLC, msgs::CommitmentSigned)> = None;
	let mut expected_next_node = expected_route.last().unwrap().node.get_our_node_id();
	macro_rules! get_next_msgs {
		($node: expr) => {
			{
				let events = $node.node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				match events[0] {
					MessageSendEvent::UpdateHTLCs { ref node_id, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
						assert!(update_add_htlcs.is_empty());
						assert_eq!(update_fulfill_htlcs.len(), 1);
						assert!(update_fail_htlcs.is_empty());
						assert!(update_fail_malformed_htlcs.is_empty());
						assert!(update_fee.is_none());
						expected_next_node = node_id.clone();
						Some((update_fulfill_htlcs[0].clone(), commitment_signed.clone()))
					},
					_ => panic!("Unexpected event"),
				}
			}
		}
	}

	macro_rules! last_update_fulfill_dance {
		($node: expr, $prev_node: expr) => {
			{
				$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
				check_added_monitors!($node, 0);
				assert!($node.node.get_and_clear_pending_msg_events().is_empty());
				commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, false);
			}
		}
	}
	macro_rules! mid_update_fulfill_dance {
		($node: expr, $prev_node: expr, $new_msgs: expr) => {
			{
				$node.node.handle_update_fulfill_htlc(&$prev_node.node.get_our_node_id(), &next_msgs.as_ref().unwrap().0).unwrap();
				check_added_monitors!($node, 1);
				let new_next_msgs = if $new_msgs {
					get_next_msgs!($node)
				} else {
					assert!($node.node.get_and_clear_pending_msg_events().is_empty());
					None
				};
				commitment_signed_dance!($node, $prev_node, next_msgs.as_ref().unwrap().1, false);
				next_msgs = new_next_msgs;
			}
		}
	}

	let mut prev_node = expected_route.last().unwrap();
	for (idx, node) in expected_route.iter().rev().enumerate() {
		assert_eq!(expected_next_node, node.node.get_our_node_id());
		let update_next_msgs = !skip_last || idx != expected_route.len() - 1;
		if next_msgs.is_some() {
			mid_update_fulfill_dance!(node, prev_node, update_next_msgs);
		} else if update_next_msgs {
			next_msgs = get_next_msgs!(node);
		} else {
			assert!(node.node.get_and_clear_pending_msg_events().is_empty());
		}
		if !skip_last && idx == expected_route.len() - 1 {
			assert_eq!(expected_next_node, origin_node.node.get_our_node_id());
		}

		prev_node = node;
	}

	if !skip_last {
		last_update_fulfill_dance!(origin_node, expected_route.first().unwrap());
		expect_payment_sent!(origin_node, our_payment_preimage);
	}
}

pub fn claim_payment(origin_node: &Node, expected_route: &[&Node], our_payment_preimage: PaymentPreimage) {
	claim_payment_along_route(origin_node, expected_route, false, our_payment_preimage);
}

pub const TEST_FINAL_CLTV: u32 = 32;

pub fn route_payment(origin_node: &Node, expected_route: &[&Node], recv_value: u64) -> (PaymentPreimage, PaymentHash) {
	let route = origin_node.router.get_route(&expected_route.last().unwrap().node.get_our_node_id(), None, &Vec::new(), recv_value, TEST_FINAL_CLTV).unwrap();
	assert_eq!(route.hops.len(), expected_route.len());
	for (node, hop) in expected_route.iter().zip(route.hops.iter()) {
		assert_eq!(hop.pubkey, node.node.get_our_node_id());
	}

	send_along_route(origin_node, route, expected_route, recv_value)
}

pub fn send_payment(origin: &Node, expected_route: &[&Node], recv_value: u64) {
	let our_payment_preimage = route_payment(&origin, expected_route, recv_value).0;
	claim_payment(&origin, expected_route, our_payment_preimage);
}

pub fn create_chan_between_nodes_with_value_init(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64) -> Transaction {
	node_a.node.create_channel(node_b.node.get_our_node_id(), channel_value, push_msat, 42).unwrap();
	node_b.node.handle_open_channel(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendOpenChannel, node_b.node.get_our_node_id())).unwrap();
	node_a.node.handle_accept_channel(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendAcceptChannel, node_a.node.get_our_node_id())).unwrap();

	let chan_id = *node_a.network_chan_count.borrow();
	let tx;
	let funding_output;

	let events_2 = node_a.node.get_and_clear_pending_events();
	assert_eq!(events_2.len(), 1);
	match events_2[0] {
		Event::FundingGenerationReady { ref temporary_channel_id, ref channel_value_satoshis, ref output_script, user_channel_id } => {
			assert_eq!(*channel_value_satoshis, channel_value);
			assert_eq!(user_channel_id, 42);

			tx = Transaction { version: chan_id as u32, lock_time: 0, input: Vec::new(), output: vec![TxOut {
				value: *channel_value_satoshis, script_pubkey: output_script.clone(),
			}]};
			funding_output = OutPoint::new(tx.txid(), 0);

			node_a.node.funding_transaction_generated(&temporary_channel_id, funding_output);
			let mut added_monitors = node_a.chan_monitor.added_monitors.lock().unwrap();
			// assert_eq!(added_monitors.len(), 1);
			// assert_eq!(added_monitors[0].0, funding_output);
			added_monitors.clear();
		},
		_ => panic!("Unexpected event"),
	}

	node_b.node.handle_funding_created(&node_a.node.get_our_node_id(), &get_event_msg!(node_a, MessageSendEvent::SendFundingCreated, node_b.node.get_our_node_id())).unwrap();
	{
		let mut added_monitors = node_b.chan_monitor.added_monitors.lock().unwrap();
		added_monitors.clear();
	}

	node_a.node.handle_funding_signed(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingSigned, node_a.node.get_our_node_id())).unwrap();
	{
		let mut added_monitors = node_a.chan_monitor.added_monitors.lock().unwrap();
		added_monitors.clear();
	}


	let events_4 = node_a.node.get_and_clear_pending_events();
	assert_eq!(events_4.len(), 1);
	match events_4[0] {
		Event::FundingBroadcastSafe { ref funding_txo, user_channel_id } => {
			assert_eq!(user_channel_id, 42);
			assert_eq!(*funding_txo, funding_output);
		},
		_ => panic!("Unexpected event"),
	};

	tx
}

pub fn create_chan_between_nodes_with_value_confirm(node_a: &Node, node_b: &Node, tx: &Transaction) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32]) {
	confirm_transaction(&node_b.chain_monitor, &tx, tx.version);
	node_a.node.handle_funding_locked(&node_b.node.get_our_node_id(), &get_event_msg!(node_b, MessageSendEvent::SendFundingLocked, node_a.node.get_our_node_id())).unwrap();

	let mut old_usable_channels = HashSet::new();
	for chan in node_a.node.list_usable_channels() {
		old_usable_channels.insert(chan.channel_id);
	}

	confirm_transaction(&node_a.chain_monitor, &tx, tx.version);

	let mut channel_id = None;
	for chan in node_a.node.list_usable_channels() {
		if !old_usable_channels.contains(&chan.channel_id) {
			channel_id = Some(chan.channel_id);
		}
	}

	let events_6 = node_a.node.get_and_clear_pending_msg_events();
	assert_eq!(events_6.len(), 2);
	((match events_6[0] {
		MessageSendEvent::SendFundingLocked { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_b.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}, match events_6[1] {
		MessageSendEvent::SendAnnouncementSignatures { ref node_id, ref msg } => {
			assert_eq!(*node_id, node_b.node.get_our_node_id());
			msg.clone()
		},
		_ => panic!("Unexpected event"),
	}), channel_id.unwrap())
}

pub fn create_chan_between_nodes_with_value_a(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64) -> ((msgs::FundingLocked, msgs::AnnouncementSignatures), [u8; 32], Transaction) {
	let tx = create_chan_between_nodes_with_value_init(node_a, node_b, channel_value, push_msat);
	let (msgs, chan_id) = create_chan_between_nodes_with_value_confirm(node_a, node_b, &tx);
	(msgs, chan_id, tx)
}

pub fn create_chan_between_nodes_with_value_b(node_a: &Node, node_b: &Node, as_funding_msgs: &(msgs::FundingLocked, msgs::AnnouncementSignatures)) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate) {
	node_b.node.handle_funding_locked(&node_a.node.get_our_node_id(), &as_funding_msgs.0).unwrap();
	let bs_announcement_sigs = get_event_msg!(node_b, MessageSendEvent::SendAnnouncementSignatures, node_a.node.get_our_node_id());
	node_b.node.handle_announcement_signatures(&node_a.node.get_our_node_id(), &as_funding_msgs.1).unwrap();

	let events_7 = node_b.node.get_and_clear_pending_msg_events();
	assert_eq!(events_7.len(), 1);
	let (announcement, bs_update) = match events_7[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			(msg, update_msg)
		},
		_ => panic!("Unexpected event"),
	};

	node_a.node.handle_announcement_signatures(&node_b.node.get_our_node_id(), &bs_announcement_sigs).unwrap();
	let events_8 = node_a.node.get_and_clear_pending_msg_events();
	assert_eq!(events_8.len(), 1);
	let as_update = match events_8[0] {
		MessageSendEvent::BroadcastChannelAnnouncement { ref msg, ref update_msg } => {
			assert!(*announcement == *msg);
			update_msg
		},
		_ => panic!("Unexpected event"),
	};

	*node_a.network_chan_count.borrow_mut() += 1;

	((*announcement).clone(), (*as_update).clone(), (*bs_update).clone())
}

pub fn create_chan_between_nodes(node_a: &Node, node_b: &Node) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_chan_between_nodes_with_value(node_a, node_b, 100000, 10001)
}

pub fn create_chan_between_nodes_with_value(node_a: &Node, node_b: &Node, channel_value: u64, push_msat: u64) -> (msgs::ChannelAnnouncement, msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	let (funding_locked, channel_id, tx) = create_chan_between_nodes_with_value_a(node_a, node_b, channel_value, push_msat);
	let (announcement, as_update, bs_update) = create_chan_between_nodes_with_value_b(node_a, node_b, &funding_locked);
	(announcement, as_update, bs_update, channel_id, tx)
}

pub fn create_announced_chan_between_nodes(nodes: &Vec<Node>, a: usize, b: usize) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	create_announced_chan_between_nodes_with_value(nodes, a, b, 100000, 10001)
}

pub fn create_announced_chan_between_nodes_with_value(nodes: &Vec<Node>, a: usize, b: usize, channel_value: u64, push_msat: u64) -> (msgs::ChannelUpdate, msgs::ChannelUpdate, [u8; 32], Transaction) {
	let chan_announcement = create_chan_between_nodes_with_value(&nodes[a], &nodes[b], channel_value, push_msat);
	for node in nodes {
		assert!(node.router.handle_channel_announcement(&chan_announcement.0).unwrap());
		node.router.handle_channel_update(&chan_announcement.1).unwrap();
		node.router.handle_channel_update(&chan_announcement.2).unwrap();
	}
	(chan_announcement.1, chan_announcement.2, chan_announcement.3, chan_announcement.4)
}

pub fn create_network(node_count: usize) -> Vec<Node> {
	let mut nodes = Vec::new();
	let secp_ctx = Secp256k1::new();

	let chan_count = Rc::new(RefCell::new(0));
	let payment_count = Rc::new(RefCell::new(0));

	for i in 0..node_count {
		let logger: Arc<Logger> = Arc::new(TestLogger::with_id(format!("node {}", i)));
		let feeest = Arc::new(TestFeeEstimator { sat_per_kw: 253 });
		let chain_monitor = Arc::new(chaininterface::ChainWatchInterfaceUtil::new(Network::Testnet, Arc::clone(&logger)));
		let tx_broadcaster = Arc::new(TestBroadcaster{txn_broadcasted: Mutex::new(Vec::new())});
		let mut seed = [42; 32]; // should be rand!
		let keys_manager = Arc::new(TestKeysInterface::new(&seed, Network::Testnet, Arc::clone(&logger)));
		let chan_monitor = Arc::new(TestChannelMonitor::new(chain_monitor.clone(), tx_broadcaster.clone(), logger.clone(), feeest.clone()));
		let mut config = UserConfig::new();
		config.channel_options.announced_channel = true;
		config.peer_channel_config_limits.force_announced_channel_preference = false;
		let node = ChannelManager::new(Network::Testnet, feeest.clone(), chan_monitor.clone(), chain_monitor.clone(), tx_broadcaster.clone(), Arc::clone(&logger), keys_manager.clone(), config).unwrap();
		let router = Router::new(secp256k1::key::PublicKey::from_secret_key(&secp_ctx, &keys_manager.get_node_secret()), chain_monitor.clone(), Arc::clone(&logger));
		nodes.push(Node { chain_monitor, tx_broadcaster, chan_monitor, node, router, keys_manager, node_seed: seed,
			network_payment_count: payment_count.clone(),
			network_chan_count: chan_count.clone(),
		});
	}
	nodes
}




// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern {
    fn alert(s: &str);
}
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn greet() {
    crate::utils::set_panic_hook();
    alert("Starting!");
	let mut nodes = create_network(2);
	let chan = create_announced_chan_between_nodes(&nodes, 0, 1);
	let channel_id = chan.2;

	// balancing
	send_payment(&nodes[0], &vec!(&nodes[1])[..], 8000000);

    alert("Ended!");
}



