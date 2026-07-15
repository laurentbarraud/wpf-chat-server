## Chat Client

An encrypted chat app built in C# and WPF that connects to a minimalist console server. <br/>
<br/>
<a href="https://github.com/laurentbarraud/wpf-chat-server/releases">
  <img src="https://img.shields.io/badge/release-stable-64B07B" alt="Release"></a>
<a href="https://github.com/laurentbarraud/wpf-chat-server/releases">
  <img src="https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/latest/total?color=88aacc&style=flat" alt="GitHub release downloads"></a>
<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/refs/heads/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="chat client screenshot" >
</p> 

It uses a homemade packet writer and parser with framed, fixed‑length packets.  
Each packet type is identified by an opcode defined in a shared library.

Message encryption was tested with multiple clients, following a full test suite that includes mixed readiness states. 
Remote connections work the same as local ones, as long as the server is reachable. 
If you're behind a router, port forwarding is required.

## Features
**Client**
- ⚙️ Async TCP networking with clean connect/disconnect cycle.
- 📦 Length‑prefixed packet framing — no desync, no corrupted packets
- 🔌 Choose the TCP port before connecting or use default
- 🏠 Runs on localhost when no IP address has been provided
- 🔐 End‑to‑end RSA 2048 bits encryption with OAEP for messages, automatic keypair generation and real‑time public key sync 
- 🔑 Public key monitor that shows a live view of all known keys and a button to request each missing one.
- 🪟 System tray integration with minimize/close to tray 
- 🎨 Light/dark theme support with instant switching 
- ✏️ Adjustable input field to match your layout preferences
- 🎞️ Subtle WPF animations using xaml storyboards
- 😀 UTF‑8 encoding for emoji-compatible messaging
- ➖ Built‑in emoji bar with smooth horizontal scrolling
- 🌐 Localized in French, Spanish and English. 

**On the roadmap for v1.1**
- [ ] 🔐 Migration of message encryption to AES, with key exchange encrypted using RSA
- [x] 💬 Bubble‑style message display
- [x] 🎨 Custom background color for outgoing message bubbles
- [ ] 🌗 Custom brightness for outgoing message bubbles, automatically switching text color when a readability contrast threshold is reached
- [x] 🔄 Toggle button to switch back to the legacy layout. 
      
**Server**
- ⚙️ Async TCP engine - handles multiple clients concurrently with non‑blocking I/O 
- 📡 Broadcast and routing logic that distributes messages to all connected clients
- 🌐 Auto‑localized server messages in French, Spanish or English, used as default fallback.

**On the roadmap for v1.1**
- [x] ✨ Non‑blocking input loop that keeps accepting clients while processing commands. 

## How to Run
1. Get the .git link from the green Code button on this page.
2. Open Visual Studio 2022 and select "Clone a repository" from the start screen.
3. Paste the .git link into the Repository Location field, choose a local folder, and click Clone.

Once the three projects are loaded:

5. Switch the build configuration to Release in the top toolbar.
6. Build the solution with Ctrl+Alt+B.

After a successful build:

7. Click the Run button in the top toolbar to start ChatServer, ChatClient and ChatProtocol at the same time.
8. Wait about 7 seconds for the server to start, then switch to the client window, enter your username in the top-left field, and press Connect or Enter.

To launch additional clients, run ChatClient.exe generated in your bin/Release folder.

## Good to Know
- Functional tests for the encryption pipeline are available [here](https://github.com/laurentbarraud/wpf-chat-server/issues/24).
- The server and client use TCP port 7123 by default.  
If that port is unavailable or blocked by a security policy, just pick any open port above 1000 and set both to use it.
- In Debug mode, a console window opens for debugging, but you can simply minimize it.
- In Release mode or when using the packaged setup, press Ctrl+K or Ctrl+M to open the monitor window. 

## Download
Go to the [Releases](../../releases) section to get a packaged setup. 
Recommended if you prefer testing without installing Visual Studio. 

Technical overview with class responsibilities (5 pages):
- English — [ChatClient-documentation.pdf](/docs/ChatClient-documentation.pdf)
- Français — [ChatClient-documentation-fr.pdf](/docs/ChatClient-documentation-fr.pdf).

### Contributing
For any suggestion of improvement or bug report, feel free to:
- Open an issue
- Submit a PR if you can code it yourself 
- Or contact me by mail.
