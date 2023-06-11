use thiserror::Error;

// Error coercion macro from here:
// https://www.reddit.com/r/rust/comments/gqfucf/comment/frwqi96/
#[macro_export]
macro_rules! Err {
	($err:expr $(,)?) => {{
		let error = $err;
		Err(anyhow::anyhow!(error))
	}};
}

#[derive(Error, Debug)]
pub enum TitanfrontError {
	#[error("Port contention issue with auth server")]
	AuthPortBind(),
	#[error("Error checking auth server liveness: {0}")]
	AuthLive(reqwest::Error),
	#[error("NorthstarMasterServer did not send server auth token")]
	NMSNoAuth(),
	#[error("NorthstarMasterServer did not send server id")]
	NMSNoID(),
	#[error("NorthstarMasterServer returned an error: {0}")]
	NMSResponse(reqwest::Error),
	#[error("Issue receiving UDP packets: {0}")]
	SwitchReceive(std::io::Error),
}
