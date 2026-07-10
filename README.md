## Chat Client
An encrypted chat application built in C# and WPF that connects locally or remotely to a minimalist console server. 
It uses a custom binary packet protocol with framed, length‑fixed packets and provides optional RSA message encryption, along with a full dark theme.

<a href="https://github.com/laurentbarraud/wpf-chat-server/releases">
  <img src="https://img.shields.io/badge/release-stable-64B07B" alt="Release"></a>
<a href="https://github.com/laurentbarraud/wpf-chat-server/releases">
  <img src="https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/latest/total?color=88aacc&style=flat" alt="GitHub release downloads"></a>
<br/>
<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/refs/heads/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="chat client screenshot" >
</p> 

## Features
**Core**
- 🔐 End‑to‑end RSA 2048 bits encryption with OAEP, automatic keypair generation and real‑time public key sync. 
- 🔑 Public Key Monitor — live view of all known keys, drives encryption state. 
- 📦 Length‑prefixed packet framing — no desync, no corrupted packets. 
- ⚡ Async TCP networking — clean connect/disconnect cycle.

**Client**
- 👥 Real‑time user list updates automatically on login/logout. 
- 😀 UTF‑8 encoding for emoji-compatible messaging. 
- ➖ Built‑in emoji bar with smooth horizontal scrolling. 
- 🔌 Choose the TCP port before connecting or use default. 
- 🏠 Runs on localhost when no IP address has been provided. 
- 🪟 System tray integration with minimize/close to tray. 
- 🎨 Light/dark themes toggle. 
- ✏️ Adjustable input field to match your layout preferences. 
- 🎞️ Subtle WPF animations using xaml storyboards. 
- 🌐 Localized in English, French and Spanish. 

**Coming soon in v1.1**
- [x] 💬 Bubble‑style message display
- [x] 🎨 Custom color for outgoing message bubbles
- [x] 🔄 Toggle to switch back to the legacy layout
- [ ] 🌗 Adaptive bubble background brightness that automatically switches text color when the contrast threshold is reached.
- [ ] 🆔 Public‑key verification with visual identity marker

**Server**
- ⚙️ Async TCP engine — handles multiple clients concurrently with non‑blocking I/O
- 📡 Broadcast & routing logic that distributes messages to all connected clients.
- 🌐 Auto‑localized server messages in French, Spanish or English, based on the OS language. 
  
## How to Run
- Clone the repository with Git  
- Open the solution file (.sln) in Visual Studio 2022  
- Build the entire solution with Ctrl+Shift+B, then run it.

In Debug mode, a console window is attached to the client at startup for debugging purposes, but you can freely minimize it.  
To avoid this, run the application in Release mode.

## Download
Go to the [Releases](../../releases) section to get a packaged installer.

Technical documentation covering class responsibilities and the encryption pipeline (5 pages):
- English — [ChatClient-documentation.pdf](/docs/ChatClient-documentation.pdf)
- Français — [ChatClient-documentation-fr.pdf](/docs/ChatClient-documentation-fr.pdf).

