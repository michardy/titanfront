use std::net::SocketAddr;

/// App
// Modification of this object is not persisted
#[derive(Clone)]
pub struct AppConfig {
	/// Server encryption key
	pub key: Vec<u8>,
	/// Server GCM tag encryption key
	pub tag_key: Vec<u8>,
	/// UDP interface and port Titanfront should expose
	pub udp_address: SocketAddr,
	/// HTTP interface and port Titanfront should expose
	pub auth_address: SocketAddr,
	/// Address for binding relays.
	/// Port number should be 0
	pub relay_address: String,
	/// Number of permitted players excluding admins
	pub player_count: usize,
	/// Size of the TCP buffer
	pub receive_buf_size: usize,
	/// Array of admin usernames
	pub admins: Vec<u64>,
	/// List of servers addresses to proxy to
	pub target_servers: Vec<SocketAddr>,
	/// Which server should new players spawn in
	pub join_target: usize,
	/// Whether to use central authentication
	pub auth_enabled: bool,
	/// URL of the central auth server
	pub auth_server: String
}

impl AppConfig {
	pub fn new() -> AppConfig {
		let mut conf = config::Config::default();

		log::info!("Setting defaults");
		conf
			.set_default("udp_address", "0.0.0.0:37015")
			.unwrap();

		conf
			.set_default("auth_address", "0.0.0.0:8081")
			.unwrap();

		conf
			.set_default("relay_address", "0.0.0.0:0")
			.unwrap();

		conf
			.set_default("player_count", 16)
			.unwrap();

		conf
			.set_default("receive_buf_size", 2048)
			.unwrap();

		conf
			.set_default("join_target", 0)
			.unwrap();

		conf
			.set_default("auth_enabled", true)
			.unwrap();

		conf
			.set_default("auth_server", "https://northstar.tf")
			.unwrap();

		log::info!("Merging configuration");
		conf
			.merge(config::File::with_name("Titanfront")).unwrap()
			.merge(config::Environment::with_prefix("Titanfront")).unwrap();

		log::info!("Building configuration struct");
		let mut admins: Vec<u64> = Vec::new();
		match conf.get_array("admins") {
			Ok(ads) => {
				for ad in ads {
					match ad.into_str() {
						Ok(s) => match s.parse::<u64>() {
							Ok(u) => admins.push(u),
							Err(_) => panic!("Bad admin ID number"),
						},
						Err(_) => {}
					}
				}
			},
			Err(_) => {}
		}

		let mut servers: Vec<SocketAddr> = Vec::new();
		match conf.get_array("target_servers") {
			Ok(servs) => {
				for serv in servs {
					match serv.into_str() {
						Ok(s) => match s.parse() {
							Ok(addr) => servers.push(addr),
							Err(_) => panic!("Bad target address")
						},
						Err(_) => {}
					}
				}
			},
			Err(_) => {}
		}
		if servers.len() == 0 {
			panic!("No target servers to proxy")
		}
		
		AppConfig {
			key: match conf.get_str("key") {
				Ok(ks) => {
					base64::decode(ks)
						.expect("Bad server key")
				},
				Err(_) => panic!("Did not specify server encryption key")
			},
			tag_key: match conf.get_str("tag_key") {
				Ok(ks) => {
					base64::decode(ks)
						.expect("Bad tag key")
				},
				Err(_) => panic!("Did not specify server GCM tag encryption key")
			},
			udp_address: match conf.get_str("udp_address") {
				Ok(saddr) => match saddr.parse() {
					Ok(addr) => addr,
					Err(_) => panic!("Bad udp address"),
				},
				Err(_) => panic!("Bad udp address")
			},
			auth_address: match conf.get_str("auth_address") {
				Ok(saddr) => match saddr.parse() {
					Ok(addr) => addr,
					Err(_) => panic!("Bad auth address"),
				},
				Err(_) => panic!("Bad auth address")
			},
			relay_address: match conf.get_str("relay_address") {
				Ok(saddr) => saddr,
				Err(_) => panic!("Bad relay address")
			},
			player_count: match conf.get_int("player_count") {
				Ok(p) => p as usize,
				Err(_) => panic!("Player number is not an int")
			},
			receive_buf_size: match conf.get_int("receive_buf_size") {
				Ok(s) => s as usize,
				Err(_) => panic!("Buffer size is not an int")
			},
			admins: admins,
			target_servers: servers,
			join_target: match conf.get_int("join_target") {
				Ok(t) => t as usize,
				Err(_) => panic!("Join target is not an int")
			},
			auth_enabled: match conf.get_bool("auth_enabled") {
				Ok(b) => b,
				Err(_) => panic!("Auth enabled is not a boolean value")
			},
			auth_server: match conf.get_str("auth_server") {
				Ok(s) => s,
				Err(_) => panic!("Auth server is not a string")
			},
		}
	}
}