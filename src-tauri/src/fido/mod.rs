#![allow(unused)]

pub mod constants;
pub mod hid;

use crate::{
	error::PFError,
	types::{
		AppConfig, AppConfigInput, DeviceInfo, FidoDeviceInfo, FullDeviceStatus, StoredCredential,
	},
};
use constants::*;
use ctap_hid_fido2::{
	Cfg, FidoKeyHidFactory, fidokey::make_credential::MakeCredentialArgs,
	public_key_credential_descriptor::PublicKeyCredentialDescriptor,
	public_key_credential_user_entity::PublicKeyCredentialUserEntity,
};
use hid::*;
use rand::Rng;
use serde_cbor_2::{Value, from_slice, to_vec};
use std::collections::{BTreeMap, HashMap};

// Fido functions that require pin: ( Uses ctap_hid_fido2 crate)

pub(crate) fn get_fido_info() -> Result<FidoDeviceInfo, String> {
	let cfg = Cfg::init();

	let device = FidoKeyHidFactory::create(&cfg)
		.map_err(|_| "Could not connect to FIDO device. Is it plugged in?".to_string())?;

	let info = device
		.get_info()
		.map_err(|e| format!("Error reading device info: {:?}", e))?;

	let options_map: HashMap<String, bool> = info.options.into_iter().collect();

	Ok(FidoDeviceInfo {
		versions: info.versions,
		extensions: info.extensions,
		aaguid: hex::encode_upper(info.aaguid),
		options: options_map,
		max_msg_size: info.max_msg_size,
		pin_protocols: info.pin_uv_auth_protocols,
		min_pin_length: info.min_pin_length,
		firmware_version: format!(
			"{}.{}",
			(info.firmware_version >> 8) & 0xFF,
			info.firmware_version & 0xFF
		),
	})
}

pub(crate) fn change_fido_pin(
	current_pin: Option<String>,
	new_pin: String,
) -> Result<String, String> {
	let cfg = Cfg::init();
	let device = FidoKeyHidFactory::create(&cfg)
		.map_err(|e| format!("Failed to connect to FIDO device: {:?}", e))?;

	match current_pin {
		Some(old) => {
			device
				.change_pin(&old, &new_pin)
				.map_err(|e| format!("Failed to change PIN: {:?}", e))?;
			Ok("PIN Changed Successfully".into())
		}
		None => {
			device
				.set_new_pin(&new_pin)
				.map_err(|e| format!("Failed to set PIN: {:?}", e))?;
			Ok("PIN Set Successfully".into())
		}
	}
}

pub(crate) fn set_min_pin_length(
	current_pin: String,
	min_pin_length: u8,
) -> Result<String, String> {
	let cfg = Cfg::init();
	let device = FidoKeyHidFactory::create(&cfg)
		.map_err(|e| format!("Failed to connect to FIDO device: {:?}", e))?;

	device
		.set_min_pin_length(min_pin_length, Some(&current_pin))
		.map_err(|e| format!("Failed to set minimum PIN length: {:?}", e))?;

	Ok(format!(
		"Minimum PIN length successfully set to {}",
		min_pin_length
	))
}

pub(crate) fn get_credentials(pin: String) -> Result<Vec<StoredCredential>, String> {
	let cfg = Cfg::init();
	let device = FidoKeyHidFactory::create(&cfg)
		.map_err(|e| format!("Failed to connect to FIDO device: {:?}", e))?;

	let rps = device
		.credential_management_enumerate_rps(Some(&pin))
		.map_err(|e| format!("Failed to enumerate Relying Parties: {:?}", e))?;

	let mut all_credentials = Vec::new();

	for rp in rps {
		let creds = device
			.credential_management_enumerate_credentials(Some(&pin), &rp.rpid_hash)
			.map_err(|e| {
				format!(
					"Failed to enumerate credentials for RP {}: {:?}",
					rp.public_key_credential_rp_entity.id, e
				)
			})?;

		for cred in creds {
			all_credentials.push(StoredCredential {
				credential_id: hex::encode(&cred.public_key_credential_descriptor.id),
				rp_id: rp.public_key_credential_rp_entity.id.clone(),
				rp_name: rp.public_key_credential_rp_entity.name.clone(),
				user_name: cred.public_key_credential_user_entity.name.clone(),
				user_display_name: cred.public_key_credential_user_entity.display_name.clone(),
				user_id: hex::encode(&cred.public_key_credential_user_entity.id).clone(),
			});
		}
	}

	Ok(all_credentials)
}

pub(crate) fn delete_credential(pin: String, credential_id_hex: String) -> Result<String, String> {
	let cfg = Cfg::init();
	let device = FidoKeyHidFactory::create(&cfg)
		.map_err(|e| format!("Failed to connect to FIDO device: {:?}", e))?;

	let cred_id_bytes = hex::decode(&credential_id_hex)
		.map_err(|_| "Invalid Credential ID Hex string".to_string())?;

	let descriptor = PublicKeyCredentialDescriptor {
		ctype: "public-key".to_string(),
		id: cred_id_bytes,
	};

	device
		.credential_management_delete_credential(Some(&pin), descriptor)
		.map_err(|e| format!("Failed to delete credential: {:?}", e))?;

	Ok("Credential deleted successfully".into())
}

// Custom Fido functions ( works only with pico-fido firmware )

pub fn read_device_details() -> Result<FullDeviceStatus, PFError> {
	log::info!("Starting FIDO device details read...");

	let transport = HidTransport::open().map_err(|e| {
		if let Some(PFError::NoDevice) = e.downcast_ref::<PFError>() {
			PFError::NoDevice
		} else {
			log::error!("Failed to open HID transport: {}", e);
			PFError::Device(e.to_string())
		}
	})?;

	// --- 1. Get Info ---
	log::debug!("Sending GetInfo command (0x04)...");
	let info_payload = [CtapCommand::GetInfo as u8];
	let info_res = transport
		.send_cbor(CTAPHID_CBOR, &info_payload)
		.map_err(|e| {
			log::error!("GetInfo CTAP command failed: {}", e);
			PFError::Device(format!("GetInfo failed: {}", e))
		})?;

	log::debug!("GetInfo response received ({} bytes)", info_res.len());

	let info_val: Value = from_slice(&info_res).map_err(|e| {
		log::error!("Failed to parse GetInfo CBOR: {}", e);
		PFError::Io(e.to_string())
	})?;

	// NOTE: Key 0x03 is AAGUID, not the unique device Serial.
	let aaguid_str = if let Value::Map(m) = &info_val {
		m.get(&Value::Integer(0x03))
			.and_then(|v| {
				if let Value::Bytes(b) = v {
					Some(hex::encode_upper(b))
				} else {
					None
				}
			})
			.unwrap_or_else(|| {
				log::warn!("AAGUID not found in GetInfo response");
				"Unknown".into()
			})
	} else {
		"Unknown".into()
	};

	let fw_version = if let Value::Map(m) = &info_val {
		m.get(&Value::Integer(0x0E))
			.and_then(|v| {
				if let Value::Integer(i) = v {
					Some(format!("{}.{}", (i >> 8) & 0xFF, i & 0xFF))
				} else {
					None
				}
			})
			.unwrap_or_else(|| {
				log::warn!("Firmware version not found in GetInfo response");
				"Unknown".into()
			})
	} else {
		"Unknown".into()
	};

	log::info!(
		"Device identified: AAGUID={}, FW={}",
		aaguid_str,
		fw_version
	);

	// --- 2. Get Memory Stats ---
	log::debug!("Preparing Memory Stats vendor command...");

	// FIX: The CBOR map should only contain the arguments ({1: 1}), not the command category.
	let mut mem_req = BTreeMap::new();
	mem_req.insert(
		Value::Integer(1), // Sub-command key (usually 1)
		Value::Integer(MemorySubCommand::GetStats as i128),
	);

	let mem_cbor = to_vec(&Value::Map(mem_req)).map_err(|e| {
		log::error!("Failed to encode Memory Stats CBOR: {}", e);
		PFError::Io(format!("CBOR encode error: {}", e))
	})?;

	// FIX: Prepend the Vendor Command ID (0x06 for Memory) to the payload
	// The firmware expects: [VendorCmdByte] [CBOR Map]
	let mut mem_payload = vec![VendorCommand::Memory as u8];
	mem_payload.extend(mem_cbor);

	log::debug!("Sending Memory Stats command...");
	let mem_res = transport
		.send_cbor(CTAP_VENDOR_CBOR_CMD, &mem_payload)
		.unwrap_or_else(|e| {
			log::warn!("Failed to fetch memory stats (Vendor Cmd): {}", e);
			Vec::new()
		});

	let mem_map: BTreeMap<i128, i128> = if !mem_res.is_empty() {
		from_slice(&mem_res).unwrap_or_else(|e| {
			log::error!("Failed to parse Memory Stats CBOR response: {}", e);
			BTreeMap::new()
		})
	} else {
		BTreeMap::new()
	};

	let used = mem_map
		.get(&(MemoryResponseKey::UsedSpace as i128))
		.cloned()
		.unwrap_or(0) as u32;
	let total = mem_map
		.get(&(MemoryResponseKey::TotalSpace as i128))
		.cloned()
		.unwrap_or(0) as u32;

	log::debug!(
		"Memory Stats: Used={}KB, Total={}KB",
		used / 1024,
		total / 1024
	);

	// --- 3. Get Physical Config ---
	log::debug!("Preparing Physical Config vendor command...");

	// FIX: Only arguments in CBOR map
	let mut phy_params = BTreeMap::new();
	phy_params.insert(
		Value::Integer(1), // Sub-command key
		Value::Integer(PhysicalOptionsSubCommand::GetOptions as i128),
	);

	// Note: The previous code nested this inside another map with key 2.
	// Based on cbor_vendor.c, we usually just send the sub-command params directly
	// or wrapped depending on the specific vendor command logic.
	// For 'PhysicalOptions', looking at cbor_vendor.c, it expects a map where key 1 is subcommand.
	// So the map we built above `phy_params` ( {1: GetOptions} ) is correct as the top-level CBOR.

	let phy_cbor = to_vec(&Value::Map(phy_params)).map_err(|e| {
		log::error!("Failed to encode Physical Config CBOR: {}", e);
		PFError::Io(format!("CBOR encode error: {}", e))
	})?;

	// FIX: Prepend Vendor Command ID (0x05 for PhysicalOptions)
	let mut phy_payload = vec![VendorCommand::PhysicalOptions as u8];
	phy_payload.extend(phy_cbor);

	log::debug!("Sending Physical Config command...");
	let phy_res = transport
		.send_cbor(CTAP_VENDOR_CBOR_CMD, &phy_payload)
		.unwrap_or_else(|e| {
			log::warn!("Failed to fetch physical config (Vendor Cmd): {}", e);
			Vec::new()
		});

	let mut config = AppConfig {
		vid: format!("{:04X}", transport.vid),
		pid: format!("{:04X}", transport.pid),
		product_name: transport.product_name.clone(),
		..Default::default()
	};

	if let Ok(Value::Map(m)) = from_slice(&phy_res) {
		log::debug!("Parsed Physical Config map successfully");
		// These keys might need adjustment based on exact firmware response structure
		// usually they are integer keys in CBOR, but if your firmware returns text keys:
		if let Some(Value::Integer(v)) = m.get(&Value::Text("gpio".into())) {
			config.led_gpio = *v as u8;
		}
		if let Some(Value::Integer(v)) = m.get(&Value::Text("brightness".into())) {
			config.led_brightness = *v as u8;
		}
	} else if !phy_res.is_empty() {
		log::warn!("Physical config response was not a valid CBOR map or empty");
	}

	log::info!("Successfully read all device details.");

	Ok(FullDeviceStatus {
		info: DeviceInfo {
			serial: "?".to_string(), // Serial number is not available through fido. Previous code was using AAGUID as serial but it is too long to display in place of serial it is already displayed somewhere else.
			flash_used: used / 1024,
			flash_total: total / 1024,
			firmware_version: fw_version,
		},
		config,
		secure_boot: false,
		secure_lock: false,
		method: "FIDO".to_string(),
	})
}

pub fn write_config(config: AppConfigInput, pin: Option<String>) -> Result<String, PFError> {
	log::info!("Starting FIDO write_config...");

	let mut byte_array = Vec::new();

	// PHY_VID = 0x0, PHY_PID is part of it
	if let (Some(vid_str), Some(pid_str)) = (&config.vid, &config.pid) {
		let vid = u16::from_str_radix(vid_str, 16).map_err(|e| PFError::Io(e.to_string()))?;
		let pid = u16::from_str_radix(pid_str, 16).map_err(|e| PFError::Io(e.to_string()))?;
		byte_array.push(0x00); // PHY_VID
		byte_array.push(4); // Length
		byte_array.push((vid >> 8) as u8);
		byte_array.push(vid as u8);
		byte_array.push((pid >> 8) as u8);
		byte_array.push(pid as u8);
	}

	// PHY_LED_GPIO = 0x4
	if let Some(gpio) = config.led_gpio {
		byte_array.push(0x04);
		byte_array.push(1);
		byte_array.push(gpio);
	}

	// PHY_LED_BTNESS = 0x5
	if let Some(brightness) = config.led_brightness {
		byte_array.push(0x05);
		byte_array.push(1);
		byte_array.push(brightness);
	}

	// PHY_UP_BUTTON = 0x8 (touch_timeout)
	if let Some(timeout) = config.touch_timeout {
		byte_array.push(0x08);
		byte_array.push(1);
		byte_array.push(timeout);
	}

	// PHY_OPTS = 0x6
	let mut opts = 0u16;
	if config.led_dimmable.unwrap_or(false) {
		opts |= 0x02; // PHY_OPT_DIMM
	}
	if !config.power_cycle_on_reset.unwrap_or(true) {
		opts |= 0x04; // PHY_OPT_DISABLE_POWER_RESET
	}
	if config.led_steady.unwrap_or(false) {
		opts |= 0x08; // PHY_OPT_LED_STEADY
	}
	byte_array.push(0x06);
	byte_array.push(2);
	byte_array.push((opts >> 8) as u8);
	byte_array.push(opts as u8);

	// PHY_ENABLED_CURVES = 0xA
	if config.enable_secp256k1.unwrap_or(false) {
		byte_array.push(0x0A);
		byte_array.push(4);
		byte_array.push(0);
		byte_array.push(0);
		byte_array.push(0);
		byte_array.push(0x08); // PHY_CURVE_SECP256K1
	}

	// PHY_USB_PRODUCT = 0x9
	if let Some(name) = &config.product_name {
		let name_bytes = name.as_bytes();
		byte_array.push(0x09);
		byte_array.push((name_bytes.len() + 1) as u8);
		byte_array.extend_from_slice(name_bytes);
		byte_array.push(0x00); // Null terminator
	}

	// PHY_LED_DRIVER = 0xC
	if let Some(driver) = config.led_driver {
		byte_array.push(0x0C);
		byte_array.push(1);
		byte_array.push(driver);
	}

	log::debug!(
		"Encoded config ({} bytes): {:02X?}",
		byte_array.len(),
		byte_array
	);

	let cfg = Cfg::init();
	let device = FidoKeyHidFactory::create(&cfg)
		.map_err(|e| PFError::Device(format!("Could not connect to FIDO device: {:?}", e)))?;

	let mut challenge = [0u8; 32];
	rand::rng().fill(&mut challenge);

	let user = PublicKeyCredentialUserEntity::new(
		Some(&byte_array),
		Some("+picoCommissionProfile"),
		Some("Pico Commissioner"),
	);

	let args = MakeCredentialArgs {
		rpid: "Pico Keys".to_string(),
		challenge: challenge.to_vec(),
		pin: pin,
		key_types: vec![],
		uv: None,
		exclude_list: vec![],
		user_entity: Some(user),
		rk: None,
		extensions: None,
	};

	device
		.make_credential_with_args(&args)
		.map_err(|e| PFError::Device(format!("MakeCredential failed: {:?}", e)))?;

	Ok("Commissioned successfully!".to_string())
}
