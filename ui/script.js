const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

let currentUsername = null;
let currentChatIp = null;
let chats = {}; // Objeto para almacenar mensajes por IP

async function join() {
    let username = document.getElementById("username").value.trim();
    let peerIp = document.getElementById("peer_ip").value.trim();

    if (!username) {
        alert("Please enter a username");
        return;
    }

    currentUsername = username; // Guardar username globalmente

    document.querySelector("#screen1").classList.replace("screen-visible", "screen-hidden");
    document.querySelector("#screen2").classList.replace("screen-hidden", "screen-visible");

    await invoke("server_listen", { username: username });

    if (peerIp) {
        await connectToPeer(peerIp, username);
    }

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

function switchChat(ip) {
    currentChatIp = ip;
    document.getElementById("connected_username").innerText = "Conectado a " + ip;
    loadChatMessages(ip);
}

function addChat() {
    // Esta función ahora simplemente enfoca el input de IP
    const input = document.getElementById("new_chat_ip");
    input.focus();
}

function addChatFromInput() {
    if (!currentUsername) {
        alert("No se encontró el nombre de usuario. Por favor inicia sesión de nuevo.");
        return;
    }

    const input = document.getElementById("new_chat_ip");
    const peerIp = input.value.trim();
    if (!peerIp) return;

    if (chats[peerIp]) {
        alert("Este chat ya existe.");
        return;
    }

    chats[peerIp] = [];
    addChatToSidebar(peerIp);
    switchChat(peerIp);
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

    await invoke("send", { message: message, is_file: false });
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

        // Si este chat está activo, también lo mostramos
        if (currentChatIp === ip) {
            document.getElementById("messages").appendChild(msgElement);
            document.getElementById("messages").scrollTop = document.getElementById("messages").scrollHeight;
        } else {
            console.log(`Mensaje recibido de ${ip}, pero no está seleccionado.`);
        }
    });

}

init();
