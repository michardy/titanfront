use crate::{appconfig::AppConfig, apperr::TitanfrontError, router::Router, Err};

use {
	actix_web::{
		dev::Server,
		get, post,
		web::{Data, Query},
		App, HttpResponse, HttpServer,
	},
	anyhow::Result,
	reqwest::multipart::{Form, Part},
	serde::{Deserialize, Serialize},
	tokio::{
		time::{sleep, Duration},
		try_join,
	},
};

use std::sync::{Arc, RwLock};

#[derive(Clone, Debug)]
struct State {
	router: Arc<Router>,
	conf: Arc<AppConfig>,
	server_auth: Arc<RwLock<String>>,
	server_id: Arc<RwLock<String>>,
}

#[derive(Deserialize, Debug)]
// These are northstar specified names provided as query parameters
#[allow(non_snake_case)]
// Some of these names are expected but currently unused
// Because they follow the northstar naming convention they cannot
// be prefixed with _
#[allow(dead_code)]
pub struct ConnectRequest {
	/// Player ID
	id: u64,
	/// Randomly generated 28 bit player auth token
	authToken: String,
	/// Token to authenticate NorthstarMasterServer instance
	serverAuthToken: String,
	username: String,
	password: Option<String>,
}

#[derive(Serialize, Debug)]
// These are northstar specified names provided as query parameters
#[allow(non_snake_case)]
// Some of these names are expected but currently unused
// Because they follow the northstar naming convention they cannot
// be prefixed with _
#[allow(dead_code)]
pub struct AddRequest {
	port: u16,
	authPort: u16,
	name: String,
	description: String,
	map: String,
	playlist: String,
	maxPlayers: u64,
	password: String,
}

#[derive(Deserialize, Debug)]
// These are northstar specified names provided as query parameters
#[allow(non_snake_case)]
// Some of these names are expected but currently unused
// Because they follow the northstar naming convention they cannot
// be prefixed with _
#[allow(dead_code)]
pub struct RequestError {
	// The field returned by northstar is a reserved word
	#[serde(rename = "enum")]
	error_id: String,
	msg: String,
}

#[derive(Deserialize, Debug)]
// These are northstar specified names provided as query parameters
#[allow(non_snake_case)]
// Some of these names are expected but currently unused
// Because they follow the northstar naming convention they cannot
// be prefixed with _
#[allow(dead_code)]
pub struct AddResponse {
	success: bool,
	id: Option<String>,
	serverAuthToken: Option<String>,
	error: Option<RequestError>,
}

#[derive(Serialize, Debug)]
// These are northstar specified names provided as query parameters
#[allow(non_snake_case)]
// Some of these names are expected but currently unused
// Because they follow the northstar naming convention they cannot
// be prefixed with _
#[allow(dead_code)]
pub struct Heartbeat {
	playerCount: u64,
	id: String,
}

#[get("/verify")]
async fn verify(_state: Data<State>) -> HttpResponse {
	HttpResponse::Ok()
		.insert_header(("X-Forwarded-By", "Titanfront"))
		.body("I am a northstar server!")
}

#[post("/authenticate_incoming_player")]
async fn auth_incoming_player(state: Data<State>, con_req: Query<ConnectRequest>) -> HttpResponse {
	let conf = &state.conf;
	// You can't seem to compare an RwGuard<String> with a String using !=
	if state
		.server_auth
		.read()
		.unwrap()
		.ne(&con_req.serverAuthToken)
	{
		return HttpResponse::Forbidden()
			.insert_header(("X-Forwarded-By", "Titanfront"))
			.content_type("application/json")
			.body("{\"success\":false}");
	}
	match state
		.router
		.add_token(con_req.authToken.clone(), con_req.id, conf)
		.await
	{
		Ok(_) => {
			return HttpResponse::Ok()
				.insert_header(("X-Forwarded-By", "Titanfront"))
				.content_type("application/json")
				.body("{\"success\":true}");
		}
		Err(_) => {
			// Northstar appears to return 200s for failures
			// HTTP status codes do not cleanly map 503 seems closest
			return HttpResponse::ServiceUnavailable()
				.insert_header(("X-Forwarded-By", "Titanfront"))
				.content_type("application/json")
				.body("{\"success\":false}");
		}
	}
}

async fn publish_server(state: &State) -> Result<()> {
	sleep(Duration::from_secs(1)).await;
	let conf = &state.conf;
	match reqwest::get(format!("http://{}/verify", conf.auth_address))
		.await?
		.text()
		.await
	{
		Ok(s) => {
			if s != "I am a northstar server!" {
				log::error!("Possible port contention");
				return Err!(TitanfrontError::AuthPortBind());
			}
		}
		Err(e) => {
			log::error!("Liveness check failed");
			return Err!(TitanfrontError::AuthLive(e));
		}
	}
	log::info!("authserver completed startup");
	if conf.auth_enabled {
		let add_req = AddRequest {
			port: conf.udp_address.port(),
			authPort: conf.auth_address.port(),
			name: conf.name.clone(),
			description: conf.description.clone(),
			map: String::from("????"),
			playlist: String::from("????"),
			maxPlayers: conf.player_count as u64,
			password: conf.password.clone(),
		};
		let client = reqwest::Client::new();
		let part = Part::text(conf.modinfo.clone())
			.file_name("modinfo.json")
			.mime_str("application/json")?;
		let form = Form::new().part("modinfo", part);
		let post_req = client
			.post(format!("{}/server/add_server", conf.auth_server))
			.header("User-Agent", format!("R2Northstar/{}", conf.version))
			.query(&add_req)
			.multipart(form)
			.header("Content-Type", "text/plain")
			.send()
			.await?
			.json::<AddResponse>();
		match post_req.await {
			Ok(r) => {
				if r.success {
					println!("SERVER ID OBSERVED:{:?}", r.id);
					let mut auth = state.server_auth.write().unwrap();
					auth.clone_from(&r.serverAuthToken.ok_or_else(TitanfrontError::NMSNoAuth)?);
					let mut id = state.server_id.write().unwrap();
					id.clone_from(&r.id.ok_or_else(TitanfrontError::NMSNoID)?);
					println!("SERVER ID VAL 0:{:?}", id);
				} else {
					log::error!("Request failed:{:?}", r);
					panic!("Could not add server");
				}
			}
			Err(e) => {
				log::error!("NorthstarMasterServer issued bad response to registration");
				return Err!(TitanfrontError::NMSResponse(e));
			}
		}
		log::debug!("SERVER ID VAL 1:{:?}", state.server_id.read().unwrap());
		loop {
			sleep(Duration::from_secs(5)).await;
			let heartbeat = Heartbeat {
				playerCount: state.router.get_player_count(),
				id: state.server_id.read().unwrap().to_string(),
			};
			let client = reqwest::Client::new();
			let part = Part::text(conf.modinfo.clone())
				.file_name("modinfo.json")
				.mime_str("application/json")?;
			let form = Form::new().part("modinfo", part);
			let heartbeat_req = client
				.post(format!("{}/server/heartbeat", conf.auth_server))
				.header("User-Agent", format!("R2Northstar/{}", conf.version))
				.query(&heartbeat)
				.multipart(form)
				.header("Content-Type", "text/plain")
				.send()
				.await?
				.text();
			match heartbeat_req.await {
				Ok(_r) => {}
				Err(e) => {
					log::error!("NorthstarMasterServer issued bad response to heartbeat");
					return Err!(TitanfrontError::NMSResponse(e));
				}
			}
		}
	} else {
		Ok(())
	}
}

async fn server_caller(server: Server) -> Result<()> {
	server.await.or_else(|err| Err!(err))
}

pub async fn build_and_run(router: Arc<Router>, conf: Arc<AppConfig>) -> Result<()> {
	// Setup authserver
	log::info!("Setting up auth server");
	let state = State {
		router,
		conf: conf.clone(),
		server_id: Arc::new(RwLock::new(String::new())),
		server_auth: Arc::new(RwLock::new(String::new())),
	};
	let authsv_state = state.clone();
	let authserver = HttpServer::new(move || {
		App::new()
			.app_data(Data::new(authsv_state.clone()))
			.service(verify)
			.service(auth_incoming_player)
	})
	.bind(conf.auth_address)?
	.run();

	let serv_caller = server_caller(authserver);
	let publish = publish_server(&state);

	log::info!("Starting auth server");

	match try_join!(publish, serv_caller) {
		Ok(_) => Ok(()),
		Err(e) => Err(e),
	}
}
