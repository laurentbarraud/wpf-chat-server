## Chat Client
WPF encrypted chat app in C#, with a console server, RSA encryption, async TCP networking and a custom packet protocol.

[![Release](https://img.shields.io/badge/release-stable-1f593d)](https://github.com/laurentbarraud/wpf-chat-server/releases)
[![GitHub release downloads](https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/latest/total?color=88aacc&style=flat)](https://github.com/laurentbarraud/wpf-chat-server/releases)

<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/refs/heads/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="chat client screenshot" >
</p>

## Features
**Core**
- 🔐 End‑to‑end RSA encryption — automatic keypair generation and real‑time public key sync
- 🔑 Public Key Monitor — live view of all known keys, drives encryption state
- 📦 Length‑prefixed packet framing — no desync, no corrupted packets
- ⚡ Async TCP networking — clean connect/disconnect cycle.

**Client**
- 👥 Real‑time user list updates automatically on login/logout
- 😀 UTF‑8 encoding for emoji-compatible messaging
- 🔌 Configurable TCP port — choose the port before connecting
- 🏠 Local mode — runs locally if no IP address is provided
- 🪟 System tray integration — minimize/close to tray
- 🎨 Theme toggle — light/dark themes switchable at any time
- 🌐 Localized in French, Spanish and English
- ✏️ Adjustable input field — resize or shift it horizontally to match your layout preferences
- 🎞️ Subtle WPF animations using xaml storyboards and UI polish.

**Coming soon**
- [x] 💬 Bubble mode with customizable colors and a modern top‑panel layout
- [x] 📄 Raw text mode — a settings toggle that switches back to the classic chat layout with the side roster. 

**Server**
- ⚙️ Async TCP engine — handles multiple clients concurrently with non‑blocking I/O
- 📡 Broadcast & routing logic — distributes messages to all connected clients.
- 🈺 Auto‑localized server messages — automatically switches between English and French based on the OS language

**Architecture**
- 🧩 MVVM‑light — clean separation of UI and logic
- 🔧 Custom packet reader/writer — opcode‑based routing.

## How to Run
- Clone the repository with Git  
- Open the solution file (.sln) in Visual Studio 2022  
- Build the entire solution with Ctrl+Shift+B, then run it.

In Debug mode, a console window is attached to the client at startup for debugging purposes, but you can freely minimize it.  
To avoid this, run the application in Release mode.

#### Warning : 🚧 Work in Progress
Some layout elements are unstable — including the message input area.
For the best experience, I recommend downloading the latest stable release or checking out the v1.0 tag in Git, which works normally.
Thank you for your patience while this update is being built.
  
## Download
Go to the [Releases](../../releases) section.

Technical documentation is available [here](/docs/ChatClient-documentation.pdf) —
Documentation technique disponible [ici](/docs/ChatClient-documentation-fr.pdf).
