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
- ✏️ Adjustable input field — resize or shift it horizontally to match your layout preferences
- 🎞️ Subtle WPF animations using xaml storyboards and UI polish
- 🌐 Localized in English, French and Spanish. 

**Coming soon**

- [x] 💬 Bubble‑style message display
- [x] 🎨 Custom color for outgoing message bubbles
- [ ] 🌗 Adjustable brightness for bubble backgrounds
- [ ] 🌓 Automatic text‑contrast switching for optimal readability
- [x] 🔄 Toggle to switch back to the classic layout (side roster + raw text mode)
- [ ] 🆔 Public‑key verification with visual identity marker

**Server**
- ⚙️ Async TCP engine — handles multiple clients concurrently with non‑blocking I/O
- 📡 Broadcast & routing logic — distributes messages to all connected clients.
- 🌐 Auto‑localized server messages — automatically switches between French, Spanish or default to English, based on the OS language. 

**Architecture** 
- 🧩 MVVM‑light — clean separation of UI and logic
- 🔧 Custom packet reader/writer — opcode‑based routing.
  
## How to Run
- Clone the repository with Git  
- Open the solution file (.sln) in Visual Studio 2022  
- Build the entire solution with Ctrl+Shift+B, then run it.

In Debug mode, a console window is attached to the client at startup for debugging purposes, but you can freely minimize it.  
To avoid this, run the application in Release mode.

#### 🚧 Work in Progress
The new UI is still evolving.
Some elements — especially the input area — may be unstable.
For a fully reliable version, download the latest stable release just below or check out the v1.0 tag in Visual Studio after cloning the repository. 
  
## Download
Go to the [Releases](../../releases) section.

Technical documentation (5 pages):
- English — [ChatClient-documentation.pdf](/docs/ChatClient-documentation.pdf)
- Français — [ChatClient-documentation-fr.pdf](/docs/ChatClient-documentation-fr.pdf).


 



