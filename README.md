## Chat Client
WPF encrypted chat app in C#, with a console server, async TCP networking, a custom packet protocol and a packet builder/parser.

<a href="https://github.com/laurentbarraud/wpf-chat-server/releases">
  <img src="https://img.shields.io/badge/release-stable-64B07B" alt="Release"></a>
<a href="https://dotnet.microsoft.com/en-us/download/dotnet/9.0">
  <img src="https://img.shields.io/badge/.NET-9-4B1D7A" alt=".NET 9"></a>
<a href="https://github.com/laurentbarraud/wpf-chat-server/releases">
  <img src="https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/latest/total?color=88aacc&style=flat" alt="GitHub release downloads"></a>
<br/>
<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/refs/heads/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="chat client screenshot" >
</p>

> 🔧 The modern layout is almost ready, new commits are coming soon. 

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

**Coming soon**
- [x] 💬 Bubble‑style message display
- [x] 🎨 Custom color for outgoing message bubbles
- [ ] 🌗 Adjustable brightness for bubble backgrounds
- [ ] 🌓 Automatic text‑contrast switching for optimal readability
- [x] 🔄 Toggle to switch back to the classic layout (side roster + raw text mode)
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
Go to the [Releases](../../releases) section.

Technical documentation (5 pages):
- English — [ChatClient-documentation.pdf](/docs/ChatClient-documentation.pdf)
- Français — [ChatClient-documentation-fr.pdf](/docs/ChatClient-documentation-fr.pdf).


 



