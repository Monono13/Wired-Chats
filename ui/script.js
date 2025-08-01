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

    currentUsername = username; // Guardar username globalmente

    await invoke("server_listen", { username: username });

    document.querySelector("#screen1").classList.replace("screen-visible", "screen-hidden");
    document.querySelector("#screen2").classList.replace("screen-hidden", "screen-visible");

    document.getElementById("connected_username").innerText = "Chatting as " + username;
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

    // Aquí agregamos la llamada al backend para cambiar la conexión activa
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
    // Esta función ahora simplemente enfoca el input de IP
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

    await invoke("send", { message: message, is_file: false, ip:currentChatIp });
    document.getElementById("message").value = "";
}

async function send_file() {
    await invoke("send_file");
}

function createMessage(message, className) {
    let container = document.createElement("div");
    className.split(" ").forEach(cls => container.classList.add(cls));

    let dateParts = new Date().toLocaleTimeString().split(":");
    let pre = document.createElement("pre");
    pre.innerHTML = message;
    pre.dataset.time = `${dateParts[0]}:${dateParts[1]}`;

    container.appendChild(pre);
    return container;
}

async function init() {
    await listen("message", (event) => {
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
            const link = document.createElement("a");
            link.href = "data:application/octet-stream;base64," + base64Data;
            link.download = fileName;
            link.innerText = fileName;
            link.classList.add("file");

            msgElement = createMessage("", "receiver");
            msgElement.appendChild(link);
        } else {
            msgElement = createMessage(msg.message, "receiver");
        }

        chats[ip].push(msgElement);

        if (currentChatIp === ip) {
            document.getElementById("messages").appendChild(msgElement);
            document.getElementById("messages").scrollTop = document.getElementById("messages").scrollHeight;
        } else {
            console.log(`Mensaje recibido de ${ip}, pero no está seleccionado.`);
        }
    });

    // ⬇️ Aquí agregas el input mask para la IP
    const ipInput = document.getElementById("new_chat_ip");

    ipInput.addEventListener("input", function (e) {
        // Eliminar todo lo que no sea dígito ni punto
        let value = e.target.value.replace(/[^\d.]/g, "");

        // Evitar que haya más de 3 puntos
        const parts = value.split(".");
        if (parts.length > 4) {
            parts.length = 4; // cortar a 4 partes máximo
        }

        // Validar que cada parte no tenga más de 3 dígitos
        for (let i = 0; i < parts.length; i++) {
            if (parts[i].length > 3) {
                parts[i] = parts[i].slice(0, 3);
            }
        }

        // Reconstruir valor con puntos
        e.target.value = parts.join(".");
    });

    // (Opcional) Auto-agregar punto si el último segmento tiene 3 dígitos y no hay 4 segmentos
    ipInput.addEventListener("keyup", function (e) {
        const val = this.value;
        const segments = val.split(".");
        const lastSegment = segments[segments.length - 1];
        if (
            (e.key >= "0" && e.key <= "9") &&
            lastSegment.length === 3 &&
            segments.length < 4 &&
            !val.endsWith(".")
        ) {
            this.value = val + ".";
        }
    });
}

init();
