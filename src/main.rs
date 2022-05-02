mod appconfig;
mod tsock;
mod authserver;
mod router;
mod apperr;

use crate::{
	tsock::TUdpSocket,
	router::{
		Router,
		external_handler,
		internal_handler
	},
};

use std::{
	net::{
		UdpSocket
	},
	thread,
	panic,
	process
};

use anyhow::Result;

#[async_std::main]
async fn main() -> Result<()> {

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

	let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        process::exit(1);
    }));

	log::info!("Spawn server receive threads");
	for s in internal_sockets {
		let cfg = conf.clone();
		let prxy = proxy_sock.try_clone().unwrap();
		let tables = auth_tables.clone();
		thread::spawn(|| {
			internal_handler(s, cfg, tables, prxy)
				// Thread errors cannot propagate back to the main thread
				// If they are unhandled by now they are fatal errors
				.unwrap();
		});
	}

	log::info!("Spawn player receive threads");
	for _ in 0..conf.player_count+conf.admins.len() {
		// Yes, clones are expensive but this is fixed startup cost
		let cfg = conf.clone();
		let prxy = proxy_sock.try_clone().unwrap();
		let tables = auth_tables.clone();
		thread::spawn(|| {
			external_handler(prxy, cfg, tables)
				// Thread errors cannot propagate back to the main thread
				// If they are unhandled by now they are fatal errors
				.unwrap();
		});
	}

	authserver::build_and_run(auth_tables, conf).await
}