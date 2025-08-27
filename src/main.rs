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
use aes_gcm::{aead::{Aead, KeyInit},Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use std::sync::{atomic::{AtomicBool, Ordering}};
use local_ip_address::local_ip;

const PORT: &str = "3333";
const STORAGE_FOLDER: &str = "received_files";
const  PASSPHRASE: &str = "LetsL@ve-W1R3dCh4T5";

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


// remember to call `.manage(MyState::default())`
#[tauri::command]
async fn get_local_ip() -> Result<String, String> {
    match local_ip() {
        Ok(ip) => Ok(ip.to_string()),
        Err(e) => Err(format!("No se pudo obtener la IP local: {}", e)),
    }
}

fn make_cipher() -> Aes256Gcm {
    // Derivamos 32 bytes desde el passphrase
    let key_hash = Sha256::digest(PASSPHRASE.as_bytes());
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_hash); // 32 bytes
    Aes256Gcm::new(key)
}

/// Cifra bytes → devuelve base64(nonce(12B) || ciphertext)
fn encrypt_to_b64(plaintext: &[u8]) -> Result<String, String> {
    let cipher = make_cipher();

    // Nonce de 12 bytes (único por mensaje)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| format!("encrypt error: {e}"))?;

    // Concatenamos nonce || ciphertext y lo base64-izamos
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(base64::encode(out))
}

/// Recibe base64(nonce||ciphertext) → devuelve bytes en claro
fn decrypt_from_b64(b64: &str) -> Result<Vec<u8>, String> {
    let cipher = make_cipher();

    let raw = base64::decode(b64).map_err(|e| format!("base64 decode: {e}"))?;
    if raw.len() < 12 {
        return Err("ciphertext too short".into());
    }
    let (nonce_bytes, ct) = raw.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ct)
        .map_err(|e| format!("decrypt error: {e}"))?;
    Ok(plaintext)
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
            VoiceCall: Arc::new(Mutex::new(None)),
            
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
            start_voice_call,
            end_voice_call,
            get_local_ip,
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
                    let enc = match encrypt_to_b64(payload.as_bytes()) {
                        Ok(s) => s,
                        Err(e) => { eprintln!("[ENC HELLO] {e}"); return; }
                    };
                    

                    {
                        let conn = state_connection.lock().await;
                        if let Some(writer_arc) = &*conn {
                            let mut writer = writer_arc.lock().await;
                            let _ = writer
                                .write_all(format!("{:010}{}", enc.len(), enc).as_bytes())
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
                let enc = match encrypt_to_b64(payload.as_bytes()) {
                    Ok(s) => s,
                    Err(e) => { eprintln!("[ENC HELLO] {e}"); return; }
                };

                {
                    let mut conn_lock = state_connection.lock().await;
                    if let Some(conn) = conn_lock.as_mut() {
                        let mut write_half = conn.lock().await;
                        let _ = write_half
                            .write_all(format!("{:010}{}", enc.len(), enc).as_bytes())
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
        let payload = serde_json::to_string(&msg).unwrap();
        // 🔐 Cifrar
        let enc = match encrypt_to_b64(payload.as_bytes()) {
            Ok(s) => s,
            Err(e) => { eprintln!("[ENC] {e}"); return; }
        };
        let data = format!("{:010}{}", enc.len(), enc);

        let mut conn_lock = connection.lock().await;
        if let Some(stream) = conn_lock.as_mut() {
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
        let enc = match encrypt_to_b64(payload.as_bytes()) {
            Ok(s) => s,
            Err(e) => { eprintln!("[ENC FILE] {e}"); return; }
        };
        let data = format!("{:010}{}", enc.len(), enc);

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

// VOICE CHAT
// Estructura que guarda la llamada activa
struct VoiceCallState {
    running: Arc<AtomicBool>,
}

#[tauri::command]
async fn start_voice_call(
    state: State<'_, AppState>,
    peer_ip: String,
) -> Result<(), String> {
    use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
    use std::thread;
    use std::net::UdpSocket;
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

    // Flag de control
    let running = Arc::new(AtomicBool::new(true));

    // Guardar en estado global para detener después
    let mut voice_call = state.VoiceCall.lock().await;
    *voice_call = Some(VoiceCallState { running: running.clone() });
    drop(voice_call);

    // Clonar flag y peer IP
    let r_flag = running.clone();
    let peer_ip_clone = peer_ip.clone();

    // Hilo principal de la llamada
    thread::spawn(move || {
        let host = cpal::default_host();

        // --- Dispositivos de entrada y salida ---
        let input = host.default_input_device()
            .or_else(|| host.input_devices().ok().and_then(|mut d| d.next()))
            .expect("No se encontró dispositivo de entrada");
        let output = host.default_output_device()
            .or_else(|| host.output_devices().ok().and_then(|mut d| d.next()))
            .expect("No se encontró dispositivo de salida");

        let config_input = input.default_input_config().unwrap();
        let config_output = output.default_output_config().unwrap();

        // --- Puertos cruzados según SO ---
        let (local_port, peer_port) = if cfg!(target_os = "windows") {
            (5001, 5000)
        } else {
            (5000, 5001)
        };

        // --- Socket UDP ---
        let socket = UdpSocket::bind(("0.0.0.0", local_port)).unwrap();
        socket.set_nonblocking(true).unwrap();

        // --- Buffer compartido para recepción ---
        let audio_buffer: Arc<Mutex<Vec<i16>>> = Arc::new(Mutex::new(Vec::new()));
        let buffer_clone = audio_buffer.clone();
        let r_flag_recv = r_flag.clone();
        let socket_recv = socket.try_clone().unwrap();

        // Hilo dedicado a recibir paquetes UDP
        thread::spawn(move || {
            let mut recv_buf = [0u8; 32768];
            while r_flag_recv.load(Ordering::SeqCst) {
                if let Ok((size, _src)) = socket_recv.recv_from(&mut recv_buf) {
                    let pcm: &[i16] = bytemuck::cast_slice(&recv_buf[..size]);
                    let mut buf = buffer_clone.lock().unwrap();
                    buf.clear();
                    buf.extend_from_slice(pcm);
                } else {
                    thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        });

        // --- Stream de entrada (mic -> red) ---
        let socket_in = socket.try_clone().unwrap();
        let r_flag_in = r_flag.clone();
        let peer_ip_in = peer_ip_clone.clone();
        let input_stream = input.build_input_stream(
            &config_input.into(),
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                if r_flag_in.load(Ordering::SeqCst) {
                    let pcm: Vec<i16> = data.iter().map(|&x| (x * i16::MAX as f32) as i16).collect();
                    let bytes: &[u8] = bytemuck::cast_slice(&pcm);
                    let _ = socket_in.send_to(bytes, (peer_ip_in.as_str(), peer_port));
                }
            },
            move |err| eprintln!("Input error: {err}"),
            None
        ).unwrap();

        // --- Stream de salida (buffer -> parlantes) ---
        let r_flag_out = r_flag.clone();
        let output_stream = output.build_output_stream(
            &config_output.into(),
            move |output: &mut [f32], _: &cpal::OutputCallbackInfo| {
                if r_flag_out.load(Ordering::SeqCst) {
                    let buf = audio_buffer.lock().unwrap();
                    for (o, &s) in output.iter_mut().zip(buf.iter()) {
                        *o = s as f32 / i16::MAX as f32;
                    }
                }
            },
            move |err| eprintln!("Output error: {err}"),
            None
        ).unwrap();

        // Activar streams
        input_stream.play().unwrap();
        output_stream.play().unwrap();

        // Mantener vivo mientras esté en llamada
        while r_flag.load(Ordering::SeqCst) {
            thread::sleep(std::time::Duration::from_millis(100));
        }
    });

    println!("[VOICE] Llamada iniciada con {}", peer_ip);
    Ok(())
}


#[tauri::command]
async fn end_voice_call(state: State<'_, AppState>) -> Result<(), String> {
    let mut voice_call = state.VoiceCall.lock().await;
    if let Some(vc) = voice_call.take() {
        vc.running.store(false, Ordering::SeqCst);
    }
    println!("[VOICE] Llamada terminada");
    Ok(())
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

fn start_reader(app: tauri::AppHandle, mut stream: OwnedReadHalf, _ip: String) {
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

            // `data` contiene la cadena base64 cifrada (no JSON)
            let enc_b64 = String::from_utf8_lossy(&data).to_string();

            // 🔓 Descifrar a bytes
            let plain = match decrypt_from_b64(&enc_b64) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[DEC] {e}");
                    continue;
                }
            };

            // Convertimos a String para parsear y para emitir al frontend
            let msg_str = match String::from_utf8(plain) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[UTF8] {e}");
                    continue;
                }
            };
            println!("[RECEIVED PLAINTEXT] {}", msg_str);

            // Intentamos parsear el mensaje JSON para guardar en DB
            match serde_json::from_str::<Message>(&msg_str) {
                Ok(msg) => {
                    let _ = conn.execute(
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
    VoiceCall: Arc<Mutex<Option<VoiceCallState>>>,

}

#[derive(Serialize, serde::Deserialize)]
struct Message {
    first_connect: bool,
    ip: String,
    username: String,
    message: String,
    is_file: bool,
}

struct VoiceCall {
    peer_ip: String,
    socket: Arc<UdpSocket>,
}