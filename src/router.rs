use crate::{
	appconfig::AppConfig,
	apperr::TitanfrontError,
	tsock::{TUdpSocket, TryClone},
	Err,
};

use std::{
	collections::HashSet,
	net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket},
	sync::{Arc, RwLock},
};

use {
	aes_gcm::{aead::KeyInit, AeadInPlace, Aes128Gcm, Nonce},
	anyhow::{Context, Result},
	dashmap::DashMap,
	ffi::clock,
	rand::{thread_rng, Rng},
};

const PLAYER_CONNECT_MESSAGE: [u8; 13] = [
	0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x00,
];
const CHALLENGE_AUTH_SERVER_MESSAGE: [u8; 9] =
	[0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x54, 0x74, 0x46, 0x72];
const AAD: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

mod ffi {
	extern "C" {
		pub fn clock() -> ::libc::clock_t;
	}
}

#[derive(PartialEq, Debug)]
enum ConnStat {
	Connecting,
	Authenticated,
	Blocked,
}

#[derive(Debug)]
struct Bind {
	status: ConnStat,
	sock: TUdpSocket,
	target: SocketAddr,
}

#[derive(Debug)]
struct PlayerInfo {}

#[derive(Clone, Debug)]
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
	players: Arc<DashMap<u64, PlayerInfo>>,
}

fn decrypt(ctext: &Vec<u8>, config: &AppConfig) -> Vec<u8> {
	let key = generic_array::GenericArray::clone_from_slice(&config.key);
	let tag = generic_array::GenericArray::clone_from_slice(&ctext[12..28]);
	let mut ptext = Vec::new();
	ptext.extend_from_slice(&ctext[28..]);
	let cipher = Aes128Gcm::new(&key);
	let nonce = Nonce::from_slice(&ctext[0..12]);
	match cipher.decrypt_in_place_detached(nonce, &AAD, &mut ptext, &tag) {
		Ok(_) => {}
		Err(e) => {
			// TODO: Break out some error types and stop dropping this
			log::error!("bad decrypt: {:?}", e);
		}
	}

	ptext.to_vec()
}

fn encrypt(ptext: &[u8], config: &AppConfig) -> Vec<u8> {
	let mut rng = thread_rng();
	let nonce = rng.gen::<[u8; 12]>();
	let key = generic_array::GenericArray::clone_from_slice(&config.key);
	let cipher = Aes128Gcm::new(&key);
	let mut ctext: Vec<u8> = Vec::new();
	ctext.extend_from_slice(ptext);
	let tag = cipher
		.encrypt_in_place_detached(&nonce.into(), &AAD, &mut ctext)
		.expect("Failed to encrypt own data"); // The source for this function cannot actually error
	[&nonce[..], &tag, &ctext].concat()
}

impl Router {
	pub fn new(internal_sockets: &Vec<TUdpSocket>) -> Router {
		Router {
			tokens: Arc::new(DashMap::new()),
			ips: Arc::new(DashMap::new()),
			sockets: Arc::new(DashMap::new()),
			counters: Arc::new(DashMap::new()),
			available: Arc::new(RwLock::new(
				internal_sockets
					.try_clone()
					.expect("Failed to clone internal sockets for route table"),
			)),
			players: Arc::new(DashMap::new()),
		}
	}
	pub fn add_token(&self, token: String, id: u64, conf: &AppConfig) -> Result<(), ()> {
		let avail = self.available.read().expect("Poisoned socket list");
		if avail.len() - conf.admins.len() > 0 {
			self.tokens.insert(token, id);
			Ok(())
		} else {
			Err(())
		}
	}
	fn relay_external(&self, payload: &Vec<u8>, addr: &SocketAddr, config: &AppConfig) {
		match self.ips.get_mut(&addr) {
			Some(mut pair) => {
				match pair.value().status {
					ConnStat::Authenticated => {
						pair.value().sock.send_to(&payload, pair.value().target);
						// Update the message relay clock
						// Used to identify which players can be dropped for inactivity
						self.counters.insert(*addr, unsafe { clock() });
						return;
					}
					ConnStat::Connecting => {
						let plain = decrypt(payload, config);
						let user_id = u64::from_le_bytes(plain[21..29].try_into().unwrap());
						let mut uname_end: usize = 29;
						// Iterate the username until we find a null terminator
						for i in 29..payload.len() {
							if payload[i] == 0 {
								uname_end = i;
								break;
							}
						}
						// Best effort. If someone knows the charset file a bug
						let user_name = String::from_utf8_lossy(&payload[29..uname_end]);

						if !config.auth_enabled {
							log::info!("Unauthenticated connection from {}:{}", user_id, user_name);
							pair.value_mut().status = ConnStat::Authenticated;
							pair.value().sock.send_to(&payload, pair.value().target);
							return;
						}

						// This is supposed to be hex. It had better work
						let token = String::from_utf8_lossy(&payload[uname_end..uname_end + 31]);
						// The Cow has to be dereferenced
						match self.tokens.get(&*token) {
							Some(kv) => {
								if kv.value() == &user_id {
									log::info!(
										"Connection with token from {}:{}",
										user_id,
										user_name
									);
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
							}
							None => {
								// Mark the IP blocked until we can delete it without deadlocking
								log::warn!(
									"Failed auth from {}:{} with token {}",
									user_id,
									user_name,
									token
								);
								pair.value_mut().status = ConnStat::Blocked;
								self.sockets.remove(&pair.value().sock);
								self.available.write().unwrap().push(
									pair.value()
										.sock
										.try_clone()
										.expect("Failed to clone socket for reassignment"),
								);
							}
						}
					}
					// Midway through cleanup on another thread.
					// Do nothing
					ConnStat::Blocked => {
						log::warn!("Connection on blocked socket");
						return;
					}
				}
			}
			None => {
				{
					// Explicit lifetime of read
					// We use unwrap because it only errors on panic
					if (self.available.read().unwrap()).len() == 0 {
						return;
					}
				}
				let plain = decrypt(payload, config);
				if plain.as_slice()[..13] == PLAYER_CONNECT_MESSAGE {
					let mut available = self.available.write().unwrap();
					let user_id = u64::from_le_bytes(plain[13..21].try_into().unwrap());
					if (available.len() > config.admins.len()
						&& self.players.contains_key(&user_id))
						|| (available.len() > 0 && config.admins.contains(&user_id))
					{
						// We can safely unwrap here because `available.len()` must be greater than 0
						let sock = available.pop().unwrap();
						sock.send_to(&payload, config.target_servers[config.join_target]);
						self.ips.insert(
							*addr,
							Bind {
								status: ConnStat::Connecting,
								sock: sock
									.try_clone()
									.expect("Error cloning socket into ip table"),
								target: config.target_servers[config.join_target],
							},
						);
						self.sockets.insert(sock, *addr);
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
			}
			None => {}
		}
	}

	pub fn get_player_count(&self) -> u64 {
		self.ips.len() as u64
	}
}

pub fn external_handler(socket: UdpSocket, config: AppConfig, routecfg: Router) -> Result<()> {
	let mut auth_ips: HashSet<IpAddr> = HashSet::new();
	let auth_addr = config
        .auth_server
        .replace("http://", "")
        .replace("https://", "")
        .replace("localhost", "127.0.0.1") // Localhost cannot be resolved
        .split(":")
        .collect::<Vec<&str>>()[0]
		.to_owned();
	log::info!("Creating special handler for auth server: {}", auth_addr);
	match auth_addr.parse::<IpAddr>() {
		Ok(ip) => {
			auth_ips.insert(ip);
		}
		Err(e) => {
			log::warn!("Error: {}", e);
			for addr in config
				.auth_server
				.replace("http://", "")
				.replace("https://", "")
				.to_socket_addrs()
				.expect("Could not derive auth server address")
			{
				auth_ips.insert(addr.ip());
			}
		}
	}
	loop {
		let mut buf: Vec<u8> = vec![0; config.receive_buf_size];
		match socket.recv_from(&mut buf) {
			Ok((rl, addr)) => {
				routecfg.relay_external(&buf[..rl].to_vec(), &addr, &config);
				if auth_ips.contains(&addr.ip()) {
					let mut challenge = Vec::from(CHALLENGE_AUTH_SERVER_MESSAGE);

					log::debug!("buf: {:?}", &buf[..rl]);
					let ptext = decrypt(&buf[..rl].to_owned(), &config);
					log::debug!("ptext: {:?}", ptext);
					let uid = &mut ptext[13..21].to_owned();
					log::debug!("uid: {:?}", uid);
					challenge.append(uid);
					let ctext = encrypt(&challenge, &config);
					match socket.send_to(&ctext, addr) {
						Ok(_) => {
							log::debug!("Response: {:?}", ctext);
							log::info!("Responded to auth server UDP query")
						}
						Err(e) => {
							log::warn!("Could not respond to auth server UDP query: {}", e)
						}
					}
				}
			}
			Err(e) => {
				log::error!("Issue receiving from external socket");
				return Err!(TitanfrontError::SwitchReceiveErr(e))
					.context("Error receiving in external handler");
			}
		}
	}
}

pub fn internal_handler(
	socket: TUdpSocket,
	config: AppConfig,
	routecfg: Router,
	proxy: UdpSocket,
) -> Result<()> {
	loop {
		let mut buf: Vec<u8> = vec![0; config.receive_buf_size];
		match socket.recv_from(&mut buf) {
			Ok((rl, _)) => {
				routecfg.relay_internal(&buf[..rl].to_vec(), &socket, &proxy);
			}
			Err(e) => {
				log::error!("Issue receiving from internal socket");
				return Err!(TitanfrontError::SwitchReceiveErr(e))
					.context("Error receiving in internal handler");
			}
		}
	}
}
