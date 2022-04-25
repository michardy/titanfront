mod appconfig;
mod tsock;
mod authserver;
mod router;

use std::{
	sync::{
		Arc,
		RwLock
	},
	net::{
		UdpSocket
	},
	thread
};

use dashmap::DashMap;
use tsock::TUdpSocket;
use router::{
	Router,
	internal_handler,
	external_handler
};

use crate::tsock::TryClone;

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
	let auth_tables = Router::new(&internal_sockets);

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

	authserver::build_and_run(auth_tables, conf).await
}
