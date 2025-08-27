const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

let currentUsername = null;
let currentChatIp = null;
let chats = {}; // Objeto para almacenar mensajes por IP

async function join() {
    let username = document.getElementById("username").value.trim();
    if (!username) {
        alert("Please enter a username");
        return;
    }

    currentUsername = username;
    await invoke("server_listen", { username: username });

    document.querySelector("#screen1").classList.replace("screen-visible", "screen-hidden");
    document.querySelector("#screen2").classList.replace("screen-hidden", "screen-visible");
    document.getElementById("connected_username").innerText = "Chatting as " + username;
}

async function mostrarIpLocal() {
    try {
        const ip = await invoke("get_local_ip");
        document.getElementById("local_ip").innerText = ip;
    } catch (err) {
        console.error("Error al obtener IP:", err);
        document.getElementById("local_ip").innerText = "Error";
    }
}

async function connectToPeer(ip, username) {
    await invoke("client_connect", { host: ip, username: username });
    if (!chats[ip]) {
        chats[ip] = [];
        addChatToSidebar(ip);
    }
    currentChatIp = ip;
    loadChatMessages(ip);
}

function addChatToSidebar(ip) {
    const li = document.createElement("li");
    li.textContent = ip;
    li.onclick = () => switchChat(ip);
    document.getElementById("chatList").appendChild(li);
}

function loadChatMessages(ip) {
    const messages = document.getElementById("messages");
    messages.innerHTML = "";
    if (chats[ip]) {
        chats[ip].forEach(msg => messages.appendChild(msg));
    }
}

async function switchChat(ip) {
    currentChatIp = ip;
    document.getElementById("connected_username").innerText = "Conectado a " + ip;

    loadChatMessages(ip);

    if (currentUsername) {
        try {
            await invoke("switch_connection", {
                ip: ip,
                username: currentUsername
            });
            console.log("[UI] Cambiada conexión a", ip);
        } catch (err) {
            console.error("[UI] Error al cambiar conexión:", err);
            alert("Error al cambiar de conexión: " + err);
        }
    }
}

function addChat() {
    const input = document.getElementById("new_chat_ip");
    input.focus();
}

function isValidIPv4(ip) {
    const regex = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
    return regex.test(ip);
}

async function addChatFromInput() {
    if (!currentUsername) {
        alert("No se encontró el nombre de usuario. Por favor inicia sesión de nuevo.");
        return;
    }

    const input = document.getElementById("new_chat_ip");
    const error = document.getElementById("ip-error");
    const peerIp = input.value.trim();

    if (!isValidIPv4(peerIp)) {
        error.style.display = "block";
        return;
    } else {
        error.style.display = "none";
    }

    if (chats[peerIp]) {
        alert("Este chat ya existe.");
        return;
    }

    chats[peerIp] = [];
    addChatToSidebar(peerIp);
    await switchChat(peerIp);
    input.value = "";
}

async function send() {
    let message = document.getElementById("message").value.trim();
    if (!message || !currentChatIp) return;

    let msgElement = createMessage(message, "sender");
    chats[currentChatIp].push(msgElement);

    const messages = document.getElementById("messages");
    messages.appendChild(msgElement);
    messages.scrollTop = messages.scrollHeight;

    await invoke("send", { message: message, is_file: false, ip: currentChatIp });
    document.getElementById("message").value = "";
}

async function send_file() {
    if (!currentChatIp) {
        alert("No hay chat seleccionado para enviar el archivo.");
        return;
    }
    await invoke("send_file");
}

// VOICE CHAT
async function openVoiceChat() {
    if (!currentChatIp) {
        alert("No hay un chat seleccionado.");
        return;
    }

    // Ocultar screen2 y mostrar screen3
    document.querySelector("#screen2").classList.replace("screen-visible", "screen-hidden");
    document.querySelector("#screen3").classList.replace("screen-hidden", "screen-visible");

    // Mostrar con quién se abrió el voice chat
    document.getElementById("voiceChatPeer").innerText = "Voice Chat con " + currentChatIp;

    // Iniciar la llamada de voz usando Rust
    try {
        await invoke("start_voice_call", { peerIp: currentChatIp });
        console.log("[VOICE] Llamada iniciada con", currentChatIp);
    } catch (err) {
        console.error("[VOICE] Error iniciando la llamada:", err);
        alert("No se pudo iniciar la llamada de voz: " + err);
    }
}

async function closeVoiceChat() {
    // Detener la llamada de voz en Rust
    try {
        await invoke("end_voice_call");
        console.log("[VOICE] Llamada terminada");
    } catch (err) {
        console.error("[VOICE] Error terminando la llamada:", err);
    }

    // Ocultar screen3 y mostrar screen2
    document.querySelector("#screen3").classList.replace("screen-visible", "screen-hidden");
    document.querySelector("#screen2").classList.replace("screen-hidden", "screen-visible");
}

// Guarda archivo recibido en received_files
async function saveReceivedFile(fileName, base64Data) {
    try {
        const savedPath = await invoke("save_file", { fileName, base64Data });
        console.log("Archivo guardado en received_files:", savedPath);
        return savedPath;
    } catch (error) {
        console.error("Error al guardar archivo:", error);
        alert("No se pudo guardar el archivo.");
        throw error;
    }
}

function createMessage(message, className, extraContent = null) {
    let container = document.createElement("div");
    className.split(" ").forEach(cls => container.classList.add(cls));

    let dateParts = new Date().toLocaleTimeString().split(":");

    if (message) {
        let pre = document.createElement("pre");
        pre.innerHTML = message;
        pre.dataset.time = `${dateParts[0]}:${dateParts[1]}`;
        container.appendChild(pre);
    }

    if (extraContent) {
        container.appendChild(extraContent);
    }

    return container;
}

async function init() {
    await listen("message", async (event) => {
        const { ip, message } = event.payload;
        let msg;

        try {
            msg = JSON.parse(message.trim());
        } catch (e) {
            console.error("Mensaje malformado:", message);
            return;
        }

        if (!chats[ip]) {
            chats[ip] = [];
            addChatToSidebar(ip);
        }

        let msgElement;

        if (msg.is_file) {
            const [fileName, base64Data] = msg.message.split("|");

            // Guardar automáticamente
            saveReceivedFile(fileName, base64Data).catch(console.error);

            // Crear enlace para descargar en carpeta de descargas
            const link = document.createElement("a");
            link.href = "#";
            link.innerText = fileName;
            link.classList.add("file");
            link.onclick = async () => {
                try {
                    const path = await invoke("download_file", { fileName, base64Data });
                    alert("Archivo descargado en: " + path);
                } catch (err) {
                    console.error("Error descargando archivo:", err);
                    alert("No se pudo descargar el archivo");
                }
            };

            msgElement = createMessage("", "receiver", link);
        } else {
            msgElement = createMessage(msg.message, "receiver");
        }

        chats[ip].push(msgElement);

        if (currentChatIp === ip) {
            const messages = document.getElementById("messages");
            messages.appendChild(msgElement);
            messages.scrollTop = messages.scrollHeight;
        }
    });

    mostrarIpLocal();

    const ipInput = document.getElementById("new_chat_ip");
    ipInput.addEventListener("input", function (e) {
        let value = e.target.value.replace(/[^\d.]/g, "");
        const parts = value.split(".");
        if (parts.length > 4) parts.length = 4;
        for (let i = 0; i < parts.length; i++) {
            if (parts[i].length > 3) parts[i] = parts[i].slice(0, 3);
        }
        e.target.value = parts.join(".");
    });

    ipInput.addEventListener("keyup", function (e) {
        const val = this.value;
        const segments = val.split(".");
        const lastSegment = segments[segments.length - 1];
        if ((e.key >= "0" && e.key <= "9") &&
            lastSegment.length === 3 &&
            segments.length < 4 &&
            !val.endsWith(".")) {
            this.value = val + ".";
        }
    });
}

async function loadSavedMessages() {
    const savedMessages = await invoke("get_messages");

    for (const msg of savedMessages) {
        const ip = msg.ip;

        if (!chats[ip]) {
            chats[ip] = [];
            addChatToSidebar(ip);
        }

        let msgElement;

        if (msg.is_file) {
            const [fileName, base64Data] = msg.message.split("|");

            // Guardar automáticamente
            saveReceivedFile(fileName, base64Data).catch(console.error);

            const link = document.createElement("a");
            link.href = "#";
            link.innerText = fileName;
            link.classList.add("file");
            link.onclick = async () => {
                try {
                    const path = await invoke("download_file", { fileName, base64Data });
                    alert("Archivo descargado en: " + path);
                } catch (err) {
                    console.error("Error descargando archivo:", err);
                    alert("No se pudo descargar el archivo");
                }
            };

            msgElement = createMessage("", "receiver", link);
        } else {
            msgElement = createMessage(msg.message, "receiver");
        }

        chats[ip].push(msgElement);
    }

    if (currentChatIp) {
        loadChatMessages(currentChatIp);
    } else {
        const ips = Object.keys(chats);
        if (ips.length > 0) switchChat(ips[0]);
    }
}

init();
loadSavedMessages();


