mod bundle;
mod manifest;

use manifest::{BundleMeta, ExtractResult, Manifest, VerifyResult};
use std::path::Path;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager};

// ── Tauri Commands ──────────────────────────────────────────────

#[tauri::command]
async fn create_tza(
    source_path: String,
    output_path: String,
    sender: Option<String>,
) -> Result<Manifest, String> {
    let src = Path::new(&source_path);
    let out = Path::new(&output_path);
    let meta = BundleMeta {
        agent: sender,
        title: None,
    };
    bundle::create_bundle(src, out, meta)
}

#[tauri::command]
async fn verify_tza(tza_path: String) -> Result<VerifyResult, String> {
    let path = Path::new(&tza_path);
    bundle::verify_bundle(path)
}

#[tauri::command]
async fn extract_tza(tza_path: String, output_dir: String) -> Result<ExtractResult, String> {
    let path = Path::new(&tza_path);
    let out = Path::new(&output_dir);
    bundle::extract_bundle(path, out, false)
}

#[tauri::command]
async fn get_tza_info(tza_path: String) -> Result<Manifest, String> {
    let result = bundle::verify_bundle(Path::new(&tza_path))?;
    result
        .manifest
        .ok_or_else(|| "No manifest found".to_string())
}

// ── System Tray ─────────────────────────────────────────────────

fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let open_item = MenuItem::with_id(app, "open", "Open TBZ", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open_item, &quit_item])?;

    TrayIconBuilder::new()
        .icon(app.default_window_icon().unwrap().clone())
        .menu(&menu)
        .tooltip("TBZ — Tibet Bundle Zipper")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(w) = app.get_webview_window("main") {
                    if w.is_visible().unwrap_or(false) {
                        let _ = w.hide();
                    } else {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                }
            }
        })
        .build(app)?;

    Ok(())
}

// ── App Entry ───────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Check CLI args for right-click integration
    let args: Vec<String> = std::env::args().collect();
    let cli_file: Option<String> = match args.get(1).map(String::as_str) {
        Some("--pack") => args.get(2).cloned(),
        Some("--verify") => args.get(2).cloned(),
        Some(path) if path.ends_with(".tza") => Some(path.to_string()),
        _ => None,
    };
    let cli_mode: Option<String> = args.get(1).cloned();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .setup(move |app| {
            // Setup system tray
            setup_tray(app)?;

            // Show window and pass CLI context
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();

                // If launched with a file, emit event to frontend
                if let Some(ref file_path) = cli_file {
                    let mode = match cli_mode.as_deref() {
                        Some("--pack") => "pack",
                        Some("--verify") => "verify",
                        _ => "verify",
                    };
                    let _ = window.emit(
                        "cli-file",
                        serde_json::json!({ "path": file_path, "mode": mode }),
                    );
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            create_tza,
            verify_tza,
            extract_tza,
            get_tza_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TBZ");
}
