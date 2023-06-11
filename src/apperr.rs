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
	AuthPortBindErr(),
	#[error("Error checking auth server liveness: {0}")]
	AuthLiveErr(reqwest::Error),
	#[error("NorthstarMasterServer did not send server auth token")]
	NMSNoAuthErr(),
	#[error("NorthstarMasterServer did not send server id")]
	NMSNoIDErr(),
	#[error("NorthstarMasterServer returned an error: {0}")]
	NMSResponseErr(reqwest::Error),
	#[error("Issue receiving UDP packets: {0}")]
	SwitchReceiveErr(std::io::Error),
}
