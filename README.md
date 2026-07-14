## Chat Client

An encrypted chat app built in C# and WPF that connects to a minimalist console server.  <br/>
<a href="https://github.com/laurentbarraud/wpf-chat-server/releases">
  <img src="https://img.shields.io/badge/release-stable-64B07B" alt="Release"></a>
<a href="https://github.com/laurentbarraud/wpf-chat-server/releases">
  <img src="https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/latest/total?color=88aacc&style=flat" alt="GitHub release downloads"></a>
<br/>
<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/refs/heads/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="chat client screenshot" >
</p> 

It uses a homemade packet writer and parser, based on a binary protocol with framed, fixed‑length packets.  
Each packet type is identified by an opcode defined in a shared library.

Message encryption was tested with multiple localhost clients and will work the same over the internet, provided the server is reachable through port forwarding.

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
- 🌐 Localized in French, Spanish and English. 

**On the roadmap for v1.1**
- [ ] 🔐 Migration of message encryption to AES, with key exchange encrypted using RSA
- [x] 💬 Bubble‑style message display
- [x] 🎨 Custom background color for outgoing message bubbles
- [ ] 🌗 Custom brightness for outgoing message bubbles, automatically switching text color when a readability contrast threshold is reached
- [x] 🔄 Toggle to switch back to the legacy layout

**Server**
- ⚙️ Async TCP engine — handles multiple clients concurrently with non‑blocking I/O
- 📡 Broadcast & routing logic that distributes messages to all connected clients.
- 🌐 Auto‑localized server messages in French, Spanish or English, used as fallback for any other OS language.

**On the roadmap for v1.1**
- [ ] Non‑blocking input loop that keeps accepting clients while processing commands

## How to Run
1. Get the .git link from the green Code button on the repository main page.
2. Open Visual Studio 2022 and select "Clone a repository" from the start screen.
3. Paste the .git link into the Repository Location field.
4. Choose a local folder and click Clone.

Once the three projects are loaded:

5. Switch the build configuration to Release.
6. Build the solution with Ctrl+Alt+B. 

After a successful build:

7. Click Run to start the server and one client instance.
8. Wait about 7 seconds for the server to start, then switch to the client window, enter your username in the top-left field and press Connect or Enter.

To launch additional clients, run ChatClient.exe from the /Release folder.

## Good to Know
- Functional tests for the encryption pipeline are available <a href="https://github.com/laurentbarraud/wpf-chat-server/issues/24">here</a>.
- The server and client use TCP port 7123 by default.
If that port is unavailable or blocked by your company, just pick any open port above 1000 and set both to use it.
- If you run the client in Debug mode in Visual Studio, a console window will be attached at startup for debugging purposes, but you can freely minimize it.  
- If you run the client in Release mode, you have to press Ctrl+K or Ctrl+M to open the monitor window - so random coworkers won't find it.

## Download
Go to the [Releases](../../releases) section to get a packaged installer. 
Recommended for stable testing or if you don’t want to install Visual Studio.

Technical overview with class responsibilities (5 pages):
- English — [ChatClient-documentation.pdf](/docs/ChatClient-documentation.pdf)
- Français — [ChatClient-documentation-fr.pdf](/docs/ChatClient-documentation-fr.pdf).

