use serde::{Deserialize, Serialize};

// --- Data Structures ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
	pub serial: String,
	pub flash_used: u32,
	pub flash_total: u32,
	pub firmware_version: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
	pub vid: String,
	pub pid: String,
	pub product_name: String,
	pub led_gpio: u8,
	pub led_brightness: u8,
	pub touch_timeout: u8,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub led_driver: Option<u8>,
	// New Options
	pub led_dimmable: bool,
	pub power_cycle_on_reset: bool,
	pub led_steady: bool,
	pub enable_secp256k1: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AppConfigInput {
	pub vid: Option<String>,
	pub pid: Option<String>,
	pub product_name: Option<String>,
	pub led_gpio: Option<u8>,
	pub led_brightness: Option<u8>,
	pub touch_timeout: Option<u8>,
	pub led_driver: Option<u8>,
	pub led_dimmable: Option<bool>,
	pub power_cycle_on_reset: Option<bool>,
	pub led_steady: Option<bool>,
	pub enable_secp256k1: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FullDeviceStatus {
	pub info: DeviceInfo,
	pub config: AppConfig,
	pub secure_boot: bool,
	pub secure_lock: bool,
}

// Fido stuff:

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FidoDeviceInfo {
	pub versions: Vec<String>,
	pub extensions: Vec<String>,
	pub aaguid: String,
	pub options: std::collections::HashMap<String, bool>,
	pub max_msg_size: i32,
	pub pin_protocols: Vec<u32>,
	// pub remaining_disc_creds: u32,
	pub min_pin_length: u32,
	pub firmware_version: String,
}

// Error stuff:

#[derive(Debug, thiserror::Error)]
pub enum AppError {
	#[error("PCSC Error: {0}")]
	Pcsc(#[from] pcsc::Error),
	#[error("IO/Hex Error: {0}")]
	Io(String),
	#[error("Device Error: {0}")]
	Device(String),
}

// Allow error to be serialized to string for Tauri
impl serde::Serialize for AppError {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(&self.to_string())
	}
}
