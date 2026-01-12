/// Custom error types for Pico Forge application.
#[derive(Debug, thiserror::Error)]
pub enum PFError {
	#[error("PCSC Error: {0}")]
	Pcsc(#[from] pcsc::Error),
	#[error("IO/Hex Error: {0}")]
	Io(String),
	#[error("Device Error: {0}")]
	Device(String),
}

// Allow error to be serialized to string for Tauri
impl serde::Serialize for PFError {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(&self.to_string())
	}
}

// pub type Result<T> = std::result::Result<T, PFError>;
