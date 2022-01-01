use std::{
	sync::{Arc, RwLock},
	net::{
		SocketAddr,
		UdpSocket
	}
};

use dashmap::DashMap;

#[derive(Clone)]
pub struct AuthTables {
	/// Map of auth tokens. 
	tokens: Arc<DashMap<String, SocketAddr>>,
	/// Map of client addresses to relay sockets
	ips: Arc<DashMap<SocketAddr, UdpSocket>>,
	// Dashmap is not really benchmarked for an update workload
	// Others are fine but this may be slow
	/// Socket use timestamps
	/// Used to disconnect dead sessions
	counters: Arc<DashMap<SocketAddr,u64>>,
	// TODO: consider making non blocking
	/// Available relay sockets
	available: Arc<RwLock<Vec<UdpSocket>>>
}


pub type Request = tide::Request<AuthTables>;

const PACKET_MAX: usize = 2048;
const PROXY_ADDR: &'static str = "10.255.0.1:37015";
const INTERNAL_INTERFACE: &'static str = "10.255.0.1:0";
const DESTINATION: &'static str = "10.255.1.1:37015";

fn relay_incoming(proxy_sock: &UdpSocket, auth_tables: &AuthTables) {
	let mut buf: [u8;2048] = [0u8;PACKET_MAX];
	match proxy_sock.recv_from(&mut buf) {
		Ok((size, addr)) => {
			// TODO: Determine if this is a no op
			if size > PACKET_MAX {
				log::warn!(
					"Dropped packet of size {}, greater than {}",
					size,
					PACKET_MAX
				);
				return
			}
			match auth_tables.ips.get(&addr) {
				Some(sock) => {
					match sock.send(&buf) {
						Ok(_) => {},
						Err(e) => log::warn!("Could not relay packet {}", e),
					}
				},
				None => {

				}
			}
		},
		Err(_) => {
			log::warn!("Received packet from unknown address")
		}
	}
}

#[async_std::main]
async fn main() -> tide::Result<()> {
	env_logger::init();

	// Setup UDP relaying sockets
	log::info!("Creating UDP sockets"); // log is not imported bc log::error would clobber error
	let proxy_sock = UdpSocket::bind(PROXY_ADDR)
		.expect("Configured proxy address could not be bound");

	let mut internal_sockets: Vec<UdpSocket> = Vec::with_capacity(16);
	for _ in 0..16 {
		let sock = UdpSocket::bind(INTERNAL_INTERFACE)
		.expect("Cannot allocate socket for client relay");
		sock.connect(DESTINATION).expect("Could not connect relay to remote");
		internal_sockets.push(sock);
	}

	log::info!("Setting up auth tables");
	let auth_tables = AuthTables {
		tokens: Arc::new(DashMap::new()),
		ips: Arc::new(DashMap::new()),
		counters: Arc::new(DashMap::new()),
		available: Arc::new(RwLock::new(internal_sockets))
	};

	// Setup authserver
	log::info!("Setting up auth server");
	let mut authserver = tide::with_state(auth_tables);
	log::info!("Starting auth server");
	authserver.listen("0.0.0.0:8081").await?;
	Ok(())
}
