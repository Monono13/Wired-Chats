const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

async function join() {
    let username = document.getElementById("username").value.trim();
    let peerIp = document.getElementById("peer_ip").value.trim();

    if (!username) {
        alert("Please enter a username");
        return;
    }

    // Cambiar pantallas
    document.querySelector("#screen1").classList.replace("screen-visible", "screen-hidden");
    document.querySelector("#screen2").classList.replace("screen-hidden", "screen-visible");

    // Iniciar servidor local SIEMPRE
    await invoke("server_listen", { username: username });

    // Conectar al peer solo si se especificó
    if (peerIp) {
        await invoke("client_connect", { host: peerIp, username: username });
    }

    document.getElementById("connected_username").innerText = "Chatting as " + username;
}

async function send() {
    let message = document.getElementById("message").value.trim();
    if (!message) return;

    let messages = document.getElementById("messages");
    messages.appendChild(createMessage(message, "sender"));
    messages.scrollTop = messages.scrollHeight;

    await invoke("send", { message: message, is_file: false });
    document.getElementById("message").value = "";
}

async function send_file() {
    await invoke("send_file");
}

async function init() {
    await listen("message", (data) => {
        let msg = JSON.parse(data.payload.trim());
        let messages = document.getElementById("messages");

        if (msg.first_connect) {
            console.log(`[CONNECTED] ${msg.username} joined`);
        } else if (msg.is_file) {
            // Procesar archivo recibido
            const [fileName, base64Data] = msg.message.split("|");

            // Crear enlace de descarga
            const link = document.createElement("a");
            link.href = "data:application/octet-stream;base64," + base64Data;
            link.download = fileName;
            link.innerText = `📁 ${fileName}`;
            link.classList.add("file");

            let container = createMessage("", "receiver");
            container.appendChild(link);
            messages.appendChild(container);
        } else {
            messages.appendChild(createMessage(msg.message, "receiver"));
        }

        messages.scrollTop = messages.scrollHeight;
    });
}

function createMessage(message, className) {
    let container = document.createElement("div");
    className.split(" ").map((cls) => {
        if (cls) container.classList.add(cls);
    });

    let dateParts = new Date().toLocaleTimeString().split(":");
    let pre = document.createElement("pre");
    pre.innerHTML = message;
    pre.dataset.time = `${dateParts[0]}:${dateParts[1]}`;

    container.appendChild(pre);
    return container;
}

init();
