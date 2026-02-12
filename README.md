## Chat Client
Encrypted chat app in C# (WPF) with a console server, using RSA encryption, async TCP networking, and a custom packet protocol.

[![Release](https://img.shields.io/badge/release-stable-245e48)](https://github.com/laurentbarraud/wpf-chat-server/releases)
[![GitHub release downloads](https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/latest/total?color=88aacc&style=flat)](https://github.com/laurentbarraud/wpf-chat-server/releases)

<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/refs/heads/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="chat client screenshot" >
</p>

### Features
#### Core
- 🔐 End‑to‑end RSA encryption — automatic keypair generation and real‑time public key sync
- 🔑 Public Key Monitor — live view of all known keys, drives encryption state
- 📦 Length‑prefixed packet framing — no desync, no corrupted packets
- 🌐 Async TCP networking — clean connect/disconnect cycle.

#### Client
- 👥 Real‑time user list — updates automatically on login/logout
- 😀 UTF‑8 messaging — emoji‑compatible
- 🔌 Configurable TCP port — choose the port before connecting
- 🏠 Local mode — runs locally if no IP address is provided
- 🪟 System tray integration — minimize/close to tray
- 🎨 Theme toggle — light/dark themes switchable at any time
- 🌐 Instant language switching — localized in French, Spanish and English
- ✏️ Adjustable input field — resize or shift it horizontally to match your layout preferences
- 🎞️ Subtle WPF animations using xaml storyboards and UI polish

#### Server
- ⚙️ Async TCP engine — handles multiple clients concurrently with non‑blocking I/O
- 📡 Broadcast & routing logic — distributes messages to all connected clients

#### Architecture
- 🧩 MVVM‑light — clean separation of UI and logic
- 🔧 Custom packet reader/writer — opcode‑based routing

### Download
Go to the [Releases](../../releases) section.

Technical documentation is available [here](/docs/ChatClient-documentation.pdf) —
Documentation technique disponible [ici](/docs/ChatClient-documentation-fr.pdf).
