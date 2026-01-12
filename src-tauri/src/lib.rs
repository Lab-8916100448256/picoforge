use serde::Serialize;
use tauri::{Emitter, Listener, Manager, WebviewWindow};

mod error;
mod fido;
mod io;
mod logging;
mod rescue;
mod types;

// This will be temporary here untill moved to a dedicated module:

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowState {
	pub is_maximized: bool,
}

/// Sets up window state listener that emits events to the frontend
pub fn setup_window_state_listener(window: &WebviewWindow) {
	let window_clone = window.clone();

	window.on_window_event(move |event| {
		if let tauri::WindowEvent::Resized(_) = event {
			if let Ok(is_maximized) = window_clone.is_maximized() {
				let _ = window_clone.emit("window-state-changed", WindowState { is_maximized });
			}
		}
	});
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
	logging::logger_init();
	log::info!("Initialisng PicoForge...");

	tauri::Builder::default()
		.plugin(tauri_plugin_shell::init())
		.plugin(tauri_plugin_opener::init())
		.setup(|app| {
			if let Some(window) = app.get_webview_window("main") {
				setup_window_state_listener(&window);
				log::info!("Window state listener initialized");
			}
			Ok(())
		})
		.invoke_handler(tauri::generate_handler![
			io::read_device_details,
			io::write_config,
			io::get_fido_info,
			io::change_fido_pin,
			io::set_min_pin_length,
			io::enable_secure_boot,
			io::reboot
		])
		.run(tauri::generate_context!())
		.expect("error while running tauri application");
}
