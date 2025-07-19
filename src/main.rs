#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::sync::Arc;
use std::fs;
use std::path::Path;
use tauri::{AppHandle, Emitter, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

const PORT: &str = "3333";
const STORAGE_FOLDER: &str = "received_files";

fn main() {
    let rt = Runtime::new().expect("Failed to create Tokio runtime");

    // Crear carpeta para archivos recibidos
    if !Path::new(STORAGE_FOLDER).exists() {
        fs::create_dir(STORAGE_FOLDER).expect("No se pudo crear la carpeta de archivos recibidos");
        println!("[INIT] Carpeta '{}' creada.", STORAGE_FOLDER);
    }

    tauri::Builder::default()
        .manage(AppState {
            streams: Arc::new(Mutex::new(Vec::new())),
            username: Arc::new(Mutex::new(String::new())),
            rt: Arc::new(rt),
        })
        .invoke_handler(tauri::generate_handler![
            server_listen,
            client_connect,
            send,
            send_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn server_listen(app: AppHandle, state: State<AppState>, username: String) {
    let rt = state.rt.clone();
    let streams = state.streams.clone();
    let username_clone = username.clone();
    let state_username = state.username.clone();

    rt.spawn(async move {
        *state_username.lock().await = username.clone();

        let listener = TcpListener::bind(format!("0.0.0.0:{}", PORT))
            .await
            .expect("Failed to bind server");

        println!("[SERVER] Listening on 0.0.0.0:{}", PORT);

        loop {
            match listener.accept().await {
                Ok((socket, addr)) => {
                    println!("[SERVER] New connection: {}", addr);

                    let (read_half, mut write_half) = socket.into_split();
                    streams.lock().await.push(write_half);

                    let msg = Message {
                        first_connect: true,
                        username: username_clone.clone(),
                        message: format!("{} connected", username_clone.clone()),
                        is_file: false,
                    };

                    let payload = serde_json::to_string(&msg).unwrap();
                    let _ = streams.lock().await.last_mut().unwrap()
                        .write_all(format!("{:010}{}", payload.len(), payload).as_bytes())
                        .await;

                    start_reader(app.clone(), read_half);
                }
                Err(e) => eprintln!("[SERVER] Connection failed: {}", e),
            }
        }
    });
}

#[tauri::command]
fn client_connect(app: AppHandle, state: State<AppState>, host: String, username: String) {
    let rt = state.rt.clone();
    let streams = state.streams.clone();
    let state_username = state.username.clone();

    rt.spawn(async move {
        *state_username.lock().await = username.clone();
        let addr = format!("{}:{}", host, PORT);

        println!("[CLIENT] Connecting to {}", addr);

        match TcpStream::connect(&addr).await {
            Ok(socket) => {
                let (read_half, mut write_half) = socket.into_split();
                streams.lock().await.push(write_half);

                let msg = Message {
                    first_connect: true,
                    username: username.clone(),
                    message: format!("{} connected", username.clone()),
                    is_file: false,
                };

                let payload = serde_json::to_string(&msg).unwrap();
                let _ = streams.lock().await.last_mut().unwrap()
                    .write_all(format!("{:010}{}", payload.len(), payload).as_bytes())
                    .await;

                start_reader(app, read_half);
            }
            Err(e) => eprintln!("[CLIENT] Failed to connect: {}", e),
        }
    });
}

#[tauri::command(rename_all = "snake_case")]
fn send(state: State<AppState>, message: String, is_file: bool) {
    let rt = state.rt.clone();
    let streams = state.streams.clone();
    let username = state.username.clone();

    rt.spawn(async move {
        let username = username.lock().await.clone();

        let msg = Message {
            first_connect: false,
            username,
            message,
            is_file,
        };

        let payload = serde_json::to_string(&msg).unwrap();
        let data = format!("{:010}{}", payload.len(), payload);

        let mut locked = streams.lock().await;
        for s in locked.iter_mut() {
            let _ = s.write_all(data.as_bytes()).await;
        }
    });
}

#[tauri::command]
fn send_file(state: State<AppState>) {
    let rt = state.rt.clone();
    let streams = state.streams.clone();
    let username = state.username.clone();

    rt.spawn(async move {
        let file_path = match rfd::FileDialog::new().pick_file() {
            Some(path) => path,
            None => {
                println!("[FILE] No se seleccionó ningún archivo");
                return;
            }
        };

        let username = username.lock().await.clone();
        let file_name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let mut file = match tokio::fs::File::open(&file_path).await {
            Ok(f) => f,
            Err(_) => {
                eprintln!("[FILE] No se pudo abrir el archivo");
                return;
            }
        };

        let mut buffer = Vec::new();
        if file.read_to_end(&mut buffer).await.is_err() {
            eprintln!("[FILE] No se pudo leer el archivo");
            return;
        }

        let encoded = base64::encode(&buffer);

        let msg = Message {
            first_connect: false,
            username,
            message: format!("{}|{}", file_name, encoded),
            is_file: true,
        };

        let payload = serde_json::to_string(&msg).unwrap();
        let data = format!("{:010}{}", payload.len(), payload);

        let mut locked = streams.lock().await;
        for s in locked.iter_mut() {
            let _ = s.write_all(data.as_bytes()).await;
        }

        println!("[FILE] Archivo '{}' enviado correctamente", file_name);
    });
}

fn start_reader(app: AppHandle, mut read_half: tokio::net::tcp::OwnedReadHalf) {
    tokio::spawn(async move {
        loop {
            let mut len_buf = [0u8; 10];
            if read_half.read_exact(&mut len_buf).await.is_err() {
                println!("[CONNECTION] Closed");
                break;
            }

            let size = match std::str::from_utf8(&len_buf)
                .unwrap()
                .trim_matches(char::from(0))
                .parse::<usize>()
            {
                Ok(s) => s,
                Err(_) => continue,
            };

            let mut data = vec![0u8; size];
            if read_half.read_exact(&mut data).await.is_err() {
                println!("[CONNECTION] Closed while reading");
                break;
            }

            let msg_str = String::from_utf8_lossy(&data).to_string();

            // ✅ Si es un archivo, lo guardamos automáticamente
            if let Ok(msg) = serde_json::from_str::<Message>(&msg_str) {
                if msg.is_file {
                    if let Some((file_name, encoded)) = msg.message.split_once("|") {
                        if let Ok(decoded) = base64::decode(encoded) {
                            let save_path = format!("{}/{}", STORAGE_FOLDER, file_name);
                            if let Err(e) = tokio::fs::write(&save_path, &decoded).await {
                                eprintln!("[FILE] Error al guardar '{}': {}", file_name, e);
                            } else {
                                println!("[FILE] Archivo '{}' guardado en '{}'", file_name, STORAGE_FOLDER);
                            }
                        }
                    }
                }
            }

            let _ = app.emit("message", msg_str);
        }
    });
}

#[derive(Clone)]
struct AppState {
    streams: Arc<Mutex<Vec<tokio::net::tcp::OwnedWriteHalf>>>,
    username: Arc<Mutex<String>>,
    rt: Arc<Runtime>,
}

#[derive(Serialize, serde::Deserialize)]
struct Message {
    first_connect: bool,
    username: String,
    message: String,
    is_file: bool,
}
