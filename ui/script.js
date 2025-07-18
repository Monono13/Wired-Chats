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
    let message = document.getElementById("message").value;
    if (!message.trim()) return;

    let messages = document.getElementById("messages");
    messages.appendChild(createMessage(message, "sender"));
    messages.scrollTop = messages.scrollHeight;

    await invoke("send", { message: message, is_emoji: false });
    document.getElementById("message").value = "";
}

async function emoji(sender) {
    let emoji = sender.innerHTML;
    let messages = document.getElementById("messages");

    messages.appendChild(createMessage(emoji, "sender emoji"));
    messages.scrollTop = messages.scrollHeight;

    await invoke("send", { message: emoji, is_emoji: true });
}

async function init() {
    await listen("message", (data) => {
        let msg = JSON.parse(data.payload.trim());
        let messages = document.getElementById("messages");

        if (msg.first_connect) {
            console.log(`[CONNECTED] ${msg.username} joined`);
        }

        messages.appendChild(
            createMessage(msg.message, "receiver " + (msg.is_emoji ? "emoji" : ""))
        );
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
