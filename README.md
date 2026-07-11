## Chat Client
An encrypted chat application built in C# and WPF that connects to a minimalist console server. 
It uses a custom binary packet protocol with framed, length‑fixed packets and provides optional message encryption. 

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
- 🔐 End‑to‑end RSA 2048 bits encryption with OAEP for messages, automatic keypair generation and real‑time public key sync. 
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
- [ ] 🔐 Migration of message encryption to AES, with key exchange encrypted using RSA
- [x] 💬 Bubble‑style message display
- [x] 🎨 Custom background color for outgoing message bubbles
- [ ] 🌗 Custom brightness for outgoing message bubbles, automatically switching text color when a readability contrast threshold is reached
- [x] 🔄 Toggle to switch back to the legacy layout

**Server**
- ⚙️ Async TCP engine — handles multiple clients concurrently with non‑blocking I/O
- 📡 Broadcast & routing logic that distributes messages to all connected clients.
- 🌐 Auto‑localized server messages in French, Spanish or English, based on the OS language. 

## How to Run
(Developer setup to get the upcoming alpha version)

1. Copy the repository’s .git link from the Code button.
2. Open Visual Studio 2022 and select “Clone a repository”.
3. Paste the .git link into the Repository Location field.
4. Choose a local folder and click Clone.

Once the three projects (ChatClient, ChatServer and ChatProtocol) are loaded:

5. Switch the build configuration to Release in the top toolbar.
6. Press Ctrl+Alt+B to build the entire solution.

After a successful build:

7. Click Run to start the server and one client instance.
8. In the client, enter your username in the top‑left field, then click Connect or press Enter.

To launch additional clients on the same machine, run ChatClient.exe located in the `/Release` folder.

In Debug mode, a console window is attached to the client at startup for debugging purposes, but you can freely minimize it.  
In Release mode, you have to press Ctrl+K or Ctrl+M to open the monitor window. 

## Download
Go to the [Releases](../../releases) section to get a packaged installer, recommended for stable testing or if you don’t want to install Visual Studio.

Technical documentation covering class responsibilities and the encryption pipeline (5 pages):
- English — [ChatClient-documentation.pdf](/docs/ChatClient-documentation.pdf)
- Français — [ChatClient-documentation-fr.pdf](/docs/ChatClient-documentation-fr.pdf).

