mod appconfig;
mod tsock;

use std::{
	sync::{
		Arc,
		RwLock
	},
	net::{
		SocketAddr,
		UdpSocket
	},
	thread
};

use appconfig::AppConfig;
use crypto::{aes_gcm::AesGcm, aead::AeadEncryptor};
use dashmap::DashMap;
use ffi::clock;
use tsock::TUdpSocket;

use crate::tsock::TryClone;

const PLAYER_CONNECT_MESSAGE: [u8; 13] = [0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x00];

mod ffi {
	extern {
		pub fn clock() -> ::libc::clock_t;
	}
}


#[derive(PartialEq)]
enum ConnStat {
	Connecting,
	Authenticated,
	Blocked
}

struct Bind {
	status: ConnStat,
	sock: TUdpSocket,
	target: SocketAddr
}

struct PlayerInfo {

}

#[derive(Clone)]
pub struct Router {
	/// Map auth tokens to user IDs to prevent spoofing
	tokens: Arc<DashMap<String, u64>>,
	/// Map of client addresses to relay sockets
	ips: Arc<DashMap<SocketAddr, Bind>>,
	/// Allows return relay threads to find client
	sockets: Arc<DashMap<TUdpSocket, SocketAddr>>,
	// Dashmap is not really benchmarked for an update workload
	// Others are fine but this may be slow
	/// Socket use timestamps
	/// Used to disconnect dead sessions
	counters: Arc<DashMap<SocketAddr, libc::clock_t>>,
	// TODO: consider making non blocking
	/// Available relay sockets
	available: Arc<RwLock<Vec<TUdpSocket>>>,
	players: Arc<DashMap<u64, PlayerInfo>>
}


pub type Request = tide::Request<Router>;

fn decrypt(ctext: &Vec<u8>, config: &AppConfig) -> Vec<u8> {
	let aad: Vec<u8> = Vec::new();
	let mut out: Vec<u8> = Vec::new();
	// TODO: avoid regenerating GCM object every call to set nonce
	let mut gcm = AesGcm::new(crypto::aes::KeySize::KeySize128, &config.key, &ctext[0..12], &aad);
	// This needs to be cloned as the original ctext may be needed if the server is vanilla
	let mut tag: Vec<u8> = Vec::from(&ctext[12..28]);
	gcm.encrypt(&ctext[28..], &mut out, &mut tag);
	out
}

impl Router {
	fn relay_external(&self, payload: &Vec<u8>, addr: &SocketAddr, config: &AppConfig) {
		match self.ips.get_mut(&addr) {
			Some(mut pair) => {
				match pair.value().status {
					ConnStat::Authenticated => {
						pair.value().sock.send_to(&payload, pair.value().target);
						// Update the message relay clock
						// Used to identify which players can be dropped for inactivity
						self.counters.insert(*addr, unsafe {clock()});
						return;
					},
					ConnStat::Connecting => {
						let plain = decrypt(payload, config);
						let user_id = u64::from_le_bytes(plain[21..29].try_into().unwrap());
						let i: usize = 29;
						// Iterate the username until we find a null terminator
						for i in 29..payload.len() {
							if payload[i] == 0 {
								break
							}
						}
						// Best effort. If someone knows the charset file a bug
						let user_name = String::from_utf8_lossy(&payload[29..i]);

						if !config.auth_enabled {
							log::info!("Unauthenticated connection from {}:{}", user_id, user_name);
							pair.value_mut().status = ConnStat::Authenticated;
							pair.value().sock.send_to(&payload, pair.value().target);
							return;
						}

						// This is supposed to be hex. It had better work
						let token = String::from_utf8_lossy(&payload[i..i+31]);
						// The Cow has to be dereferenced
						match self.tokens.get(&*token) {
							Some(kv) => {
								if kv.value() == &user_id {
									log::info!("Connection with token from {}:{}", user_id, user_name);
									pair.value_mut().status = ConnStat::Authenticated;
									pair.value().sock.send_to(&payload, pair.value().target);
									return;
								} else {
									log::info!(
										"Connection denied due to user {} spoofing {}:{}",
										kv.value(),
										user_id,
										user_name
									);
									return;
								}
							},
							None => {
								// Mark the IP blocked until we can delete it without deadlocking
								log::warn!("Failed auth from {}:{} with token {}", user_id, user_name, token);
								pair.value_mut().status = ConnStat::Blocked;
								self.available.write().unwrap().push(
									pair.value().sock.try_clone()
										.expect("Failed to clone socket for reassignment")
								);
							},
						}
					},
					// Midway throught cleanup on another thread.
					// Do nothing
					ConnStat::Blocked => {
						log::warn!("Connection on blocked socket");
						return;
					}
				}
			}
			None => {
				{ // Explicit lifetime of read
					// We use unwrap because it only errors on panic
					if (self.available.read().unwrap()).len() == 0 {
						return;
					}
				}
				let plain = decrypt(payload, config);
				if plain.as_slice()[..13] == PLAYER_CONNECT_MESSAGE {
					let mut available = self.available.write().unwrap();
					let user_id = u64::from_le_bytes(plain[13..21].try_into().unwrap());
					if (available.len() > config.admins.len() && self.players.contains_key(&user_id)) ||
					(available.len() > 0 && config.admins.contains(&user_id)) {
						// We can safely unwrap here because `available.len()` must be greater than 0
						let sock = available.pop().unwrap();
						sock.send_to(&payload, config.target_servers[config.join_target]);
						self.ips.insert(*addr, Bind {
							status: ConnStat::Connecting,
							sock: sock,
							target: config.target_servers[config.join_target]
						});
						return;
					} else {
						log::warn!("Connection blocked. Not enough sockets");
						return;
					}
				} else {
					log::warn!("Connection blocked. Bad packet");
					return;
				}
			}
		}
		log::info!("Cleaning up closed socket");
		// TODO: clean up this removal
		// It has to go outside the scope of the switch's borrow or it might race
		// Alternatly use a struct that does not race so much
		let kv = self.ips.remove(&addr);
		// Check to make sure we are not deleting in use IPs
		assert!(kv.unwrap().1.status == ConnStat::Blocked);
	}

	fn relay_internal(&self, payload: &Vec<u8>, sender: &TUdpSocket, proxy: &UdpSocket) {
		match self.sockets.get(&sender) {
			Some(pair) => {
				proxy.send_to(&payload, pair.value());
			},
			None => {},
		}
	}
}

fn external_handler(socket: UdpSocket, config: AppConfig, routecfg: Router) {
	loop {
		let mut buf: Vec<u8> = vec![0; config.receive_buf_size];
		match socket.recv_from(&mut buf) {
			Ok((_, addr)) => {
				routecfg.relay_external(&buf, &addr, &config);
			},
			Err(_) => {
				panic!("Error receiving")
			},
		}
	}
}

fn internal_handler(socket: TUdpSocket, config: AppConfig, routecfg: Router, proxy: UdpSocket) {
	loop {
		let mut buf: Vec<u8> = vec![0; config.receive_buf_size];
		match socket.recv_from(&mut buf) {
			Ok((_, _)) => {
				routecfg.relay_internal(&buf, &socket, &proxy);
			},
			Err(_) => {
				panic!("Error receiving")
			},
		}
	}
}

#[async_std::main]
async fn main() -> tide::Result<()> {

	env_logger::init();

	log::info!("Parsing config");
	let conf = appconfig::AppConfig::new();

	log::info!("Create UDP sockets");
	// Setup UDP relaying sockets
	let proxy_sock = UdpSocket::bind(conf.udp_address)?;
	let mut internal_sockets: Vec<TUdpSocket> = Vec::with_capacity(16);
	log::info!("Binding UDP sockets");
	for i in 0..conf.player_count+conf.admins.len() {
		internal_sockets.push(
			TUdpSocket::bind(&conf.relay_address, i)
				.expect("Failed to create internal socket")
		);
	}

	log::info!("Create route tables");
	let auth_tables = Router {
		tokens: Arc::new(DashMap::new()),
		ips: Arc::new(DashMap::new()),
		sockets: Arc::new(DashMap::new()),
		counters: Arc::new(DashMap::new()),
		available: Arc::new(RwLock::new(
			internal_sockets.try_clone()
				.expect("Failed to clone internal sockets for route table")
		)),
		players: Arc::new(DashMap::new())
	};

	log::info!("Spawn server receive threads");
	for s in internal_sockets {
		let cfg = conf.clone();
		let prxy = proxy_sock.try_clone().unwrap();
		let tables = auth_tables.clone();
		thread::spawn(|| {
			internal_handler(s, cfg, tables, prxy);
		});
	}

	log::info!("Spawn player receive threads");
	for _ in 0..conf.player_count+conf.admins.len() {
		// Yes, clones are expensive but this is fixed startup cost
		let cfg = conf.clone();
		let prxy = proxy_sock.try_clone().unwrap();
		let tables = auth_tables.clone();
		thread::spawn(|| {
			external_handler(prxy, cfg, tables);
		});
	}

	// Setup authserver
	log::info!("Setting up auth server");
	let authserver = tide::with_state(auth_tables);
	log::info!("Starting auth server");
	authserver.listen(conf.auth_address).await?;
	Ok(())
}
