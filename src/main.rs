#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::sync::Arc;
use std::fs;
use std::path::Path;
use tauri::{AppHandle, Emitter, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf, tcp::OwnedReadHalf};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use serde_json::json;
use rusqlite::{Connection, Result};
use std::fs::File;
use std::io::Write;
use dirs;

const PORT: &str = "3333";
const STORAGE_FOLDER: &str = "received_files";

fn init_db() -> Result<()> {
    let conn = Connection::open("chat.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            is_file INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    Ok(())
}

fn main() {
    init_db().expect("No se pudo inicializar la base de datos");

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
            connection: Arc::new(Mutex::new(None)),
            current_ip: Arc::new(Mutex::new(None)),
            ips: Arc::new(Mutex::new(Vec::new())),
        })
        .invoke_handler(tauri::generate_handler![
            server_listen,
            client_connect,
            send,
            send_file,
            switch_connection,
            get_messages,
            save_file,
            download_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
async fn server_listen<'a>(
    app: AppHandle,
    state: State<'a, AppState>,
    username: String,
) -> Result<(), String> {
    let rt = state.rt.clone();
    let streams = state.streams.clone();
    let ips = state.ips.clone();
    let username_clone = username.clone();
    let state_username = state.username.clone();
    let state_connection = state.connection.clone();

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

                    let (read_half, write_half) = socket.into_split();

                    // Guardamos la conexión en el vector de conexiones
                    {
                        let wrapped = Arc::new(Mutex::new(write_half));
                        streams.lock().await.push(wrapped.clone());

                        let mut conn_lock = state_connection.lock().await;
                        *conn_lock = Some(wrapped);
                    }

                    // Guardamos la IP también (esto puede ir separado si prefieres)
                    ips.lock().await.push(addr.ip().to_string());

                    let msg = Message {
                        first_connect: true,
                        ip: addr.ip().to_string(),
                        username: username_clone.clone(),
                        message: format!("{} connected", username_clone.clone()),
                        is_file: false,
                    };

                    let payload = serde_json::to_string(&msg).unwrap();

                    {
                        let conn = state_connection.lock().await;
                        if let Some(writer_arc) = &*conn {
                            let mut writer = writer_arc.lock().await;
                            let _ = writer
                                .write_all(format!("{:010}{}", payload.len(), payload).as_bytes())
                                .await;
                        }
                    }

                    start_reader(app.clone(), read_half, addr.ip().to_string());
                }

                Err(e) => eprintln!("[SERVER] Connection failed: {}", e),
            }
        }
    });

    Ok(())
}

#[tauri::command]
fn client_connect(app: AppHandle, state: State<AppState>, host: String, username: String, ip: String) {
    let rt = state.rt.clone();
    let state_username = state.username.clone();
    let state_connection = state.connection.clone();

    rt.spawn(async move {
        *state_username.lock().await = username.clone();
        let addr = format!("{}:{}", host, PORT);

        println!("[CLIENT] Connecting to {}", addr);

        match TcpStream::connect(&addr).await {
            Ok(socket) => {
                let (read_half, write_half) = socket.into_split();

                {
                    let mut conn_lock = state_connection.lock().await;
                    *conn_lock = Some(Arc::new(Mutex::new(write_half)));

                }

                let msg = Message {
                    first_connect: true,
                    ip: ip.clone(),
                    username: username.clone(),
                    message: format!("{} connected", username.clone()),
                    is_file: false,
                };

                let payload = serde_json::to_string(&msg).unwrap();
                {
                    let mut conn_lock = state_connection.lock().await;
                    if let Some(conn) = conn_lock.as_mut() {
                        let mut write_half = conn.lock().await;
                        let _ = write_half
                            .write_all(format!("{:010}{}", payload.len(), payload).as_bytes())
                            .await;
                    }

                }

                start_reader(app, read_half, ip);
            }
            Err(e) => eprintln!("[CLIENT] Failed to connect: {}", e),
        }
    });
}

#[tauri::command(rename_all = "snake_case")]
fn send(state: State<AppState>,ip: String, message: String, is_file: bool) {
    let rt = state.rt.clone();
    let username = state.username.clone();
    let connection = state.connection.clone();

    rt.spawn(async move {
        let username = username.lock().await.clone();

        // Definimos msg aquí para que esté visible en todo el async
        let msg = Message {
            first_connect: false,
            ip: ip.clone(),
            username: username.clone(),
            message: message.clone(),
            is_file,
        };

        // Enviamos mensaje si hay conexión
        let mut conn_lock = connection.lock().await;
        if let Some(stream) = conn_lock.as_mut() {
            let payload = serde_json::to_string(&msg).unwrap();
            let data = format!("{:010}{}", payload.len(), payload);

            let mut write_half = stream.lock().await;
            if let Err(e) = write_half.write_all(data.as_bytes()).await {
                eprintln!("[SEND] Error enviando datos: {}", e);
            }
        } else {
            eprintln!("[SEND] No hay conexión activa");
        }

        // Guardamos el mensaje en SQLite (si la base está accesible)
        // Esto puede ser un unwrap o manejar el error mejor
        match Connection::open("chat.db") {
            Ok(conn) => {
                let res = conn.execute(
                    "INSERT INTO messages (ip, username, message, is_file) VALUES (?1, ?2, ?3, ?4)",
                    (&ip, &username, &message, is_file as i32),
                );
                if let Err(e) = res {
                    eprintln!("[SQLITE] Error insertando mensaje: {}", e);
                }
            }
            Err(e) => {
                eprintln!("[SQLITE] No se pudo abrir la base de datos: {}", e);
            }
        }
    });
}

#[tauri::command]
fn send_file(state: State<AppState>) {
    let rt = state.rt.clone();
    let connection = state.connection.clone();
    let username = state.username.clone();
    let current_ip = state.current_ip.clone(); // no hacemos lock aquí

    rt.spawn(async move {
        let file_path = match rfd::FileDialog::new().pick_file() {
            Some(path) => path,
            None => {
                println!("[FILE] No se seleccionó ningún archivo");
                return;
            }
        };

        let username = username.lock().await.clone();
        let ip = current_ip.lock().await.clone().expect("No hay IP activa");

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
            ip,
            username,
            message: format!("{}|{}", file_name, encoded),
            is_file: true,
        };

        let payload = serde_json::to_string(&msg).unwrap();
        let data = format!("{:010}{}", payload.len(), payload);

        let mut conn_lock = connection.lock().await;
        if let Some(stream) = conn_lock.as_mut() {
            let mut write_half = stream.lock().await;
            if let Err(e) = write_half.write_all(data.as_bytes()).await {
                eprintln!("[FILE] Error al enviar archivo: {}", e);
            } else {
                println!("[FILE] Archivo '{}' enviado correctamente", file_name);
            }
        } else {
            eprintln!("[FILE] No hay conexión activa para enviar el archivo");
        }
    });
}

#[tauri::command]
fn save_file(file_name: String, base64_data: String) -> Result<String, String> {
    let decoded = base64::decode(&base64_data).map_err(|e| e.to_string())?;
    let path = std::path::Path::new(STORAGE_FOLDER).join(&file_name);

    let mut file = File::create(&path).map_err(|e| e.to_string())?;
    file.write_all(&decoded).map_err(|e| e.to_string())?;

    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
fn download_file(file_name: String, base64_data: String) -> Result<String, String> {
    let decoded = base64::decode(&base64_data).map_err(|e| e.to_string())?;
    
    let download_dir = dirs::download_dir().ok_or("No se pudo obtener carpeta de descargas")?;
    let path = download_dir.join(&file_name);

    let mut file = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    file.write_all(&decoded).map_err(|e| e.to_string())?;

    Ok(path.to_string_lossy().to_string())
}

#[tauri::command]
async fn switch_connection(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    ip: String,
) -> Result<(), String> {
    let mut connection_lock = state.connection.lock().await;
    let mut current_ip_lock = state.current_ip.lock().await;

    println!("[SWITCH] Solicitado cambio de conexión a {}", ip);

    // Cierra la conexión anterior si existe
    if let Some(old_write) = connection_lock.take() {
        if let Ok(mut locked) = old_write.try_lock() {
            let _ = locked.shutdown().await;
            println!("[SWITCH] Conexión anterior cerrada");
        }
    }

    // Prepara la nueva dirección con puerto
    let addr = format!("{}:3333", ip);
    println!("[SWITCH] Intentando conectar a: {}", addr);

    // Intenta conectar al nuevo IP
    match TcpStream::connect(&addr).await {
        Ok(socket) => {
            let (read_half, write_half) = socket.into_split();

            // Guarda la nueva conexión
            *connection_lock = Some(Arc::new(Mutex::new(write_half)));
            *current_ip_lock = Some(ip.clone());

            println!("[SWITCH] Conectado a {}", ip);

            // Inicia el listener con la nueva conexión
            start_reader(app, read_half, ip.clone());

            Ok(())
        }
        Err(e) => {
            eprintln!("[SWITCH] Falló la conexión: {}", e);
            Err(format!("No se pudo conectar a {}: {}", addr, e))
        }
    }
}

#[tauri::command]
fn get_messages() -> Vec<Message> {
    let conn = Connection::open("chat.db").unwrap();

    let mut stmt = conn
        .prepare("SELECT ip, username, message, is_file FROM messages ORDER BY timestamp ASC")
        .unwrap();

    let rows = stmt
        .query_map([], |row| {
            Ok(Message {
                first_connect: false,
                ip: row.get(0)?,
                username: row.get(1)?,
                message: row.get(2)?,
                is_file: row.get::<_, i32>(3)? != 0,
            })
        })
        .unwrap();

    rows.filter_map(|r| r.ok()).collect()
}

fn start_reader(app: tauri::AppHandle, mut stream: OwnedReadHalf, ip: String) {
    tokio::spawn(async move {
        let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip().to_string());

        // Abrimos la conexión a la base una sola vez para el reader
        let conn = match Connection::open("chat.db") {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[SQLITE] Error abriendo DB en reader: {}", e);
                return; // No continuamos si falla abrir DB
            }
        };

        loop {
            let mut len_buf = [0u8; 10];

            if stream.read_exact(&mut len_buf).await.is_err() {
                println!("[CONNECTION] Closed (length read)");
                break;
            }

            let size = match std::str::from_utf8(&len_buf)
                .unwrap_or("")
                .trim_matches(char::from(0))
                .parse::<usize>()
            {
                Ok(s) => s,
                Err(_) => {
                    println!("[ERROR] Tamaño inválido");
                    continue;
                }
            };

            let mut data = vec![0u8; size];

            if stream.read_exact(&mut data).await.is_err() {
                println!("[CONNECTION] Closed (data read)");
                break;
            }

            let msg_str = String::from_utf8_lossy(&data).to_string();
            println!("[RECEIVED] {}", msg_str);

            // Intentamos parsear el mensaje JSON para guardar en DB
            match serde_json::from_str::<Message>(&msg_str) {
                Ok(msg) => {
                    let res = conn.execute(
                        "INSERT INTO messages (ip, username, message, is_file) VALUES (?1, ?2, ?3, ?4)",
                        (&msg.ip, &msg.username, &msg.message, msg.is_file as i32),
                    );
                }
                Err(e) => eprintln!("[PARSE] Error parseando mensaje: {}", e),
            }


            if let Some(ip) = &peer_ip {
                let payload = json!({
                    "ip": ip,
                    "message": msg_str
                });
                if let Err(e) = app.emit("message", payload) {
                    eprintln!("[EMIT] Error al emitir mensaje: {}", e);
                }
            }
        }

        println!("[READER] Terminó la conexión del peer.");
    });
}

#[derive(Clone)]
struct AppState {
    streams: Arc<Mutex<Vec<Arc<Mutex<OwnedWriteHalf>>>>>,
    username: Arc<Mutex<String>>,
    rt: Arc<Runtime>,
    connection: Arc<Mutex<Option<Arc<Mutex<OwnedWriteHalf>>>>>,
    current_ip: Arc<Mutex<Option<String>>>,
    ips: Arc<Mutex<Vec<String>>>,
}

#[derive(Serialize, serde::Deserialize)]
struct Message {
    first_connect: bool,
    ip: String,
    username: String,
    message: String,
    is_file: bool,
}