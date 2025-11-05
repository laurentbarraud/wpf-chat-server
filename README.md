### WPF chat app with server in C#

An open source chat server and WPF client. 

[![Release](https://img.shields.io/badge/release-stable-1B4636)](https://github.com/laurentbarraud/wpf-chat-server/releases)
[![GitHub release downloads](https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/v0.9/total?color=88aacc&style=flat)](https://github.com/laurentbarraud/wpf-chat-server/releases/tag/v0.9)

<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/refs/heads/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="screenshot of chat server and client" >
</p>

 ### Features

- Packet protocol with opcodes — both server and client use a packet format that includes an opcode so receivers can identify packet types.  
- Real‑time user list — the client shows connected users and updates automatically on login/logout.  
- Configurable TCP port — the client can choose the TCP port before connecting; the server accepts a custom bind port at startup.  
- Local mode — the client will run locally if no IP address is provided.
- Last‑IP memory — the client remembers the last successful IP for faster reconnection.  
- UTF‑8 message encoding — messages use UTF‑8 (emoji supported); an emoji toolbar is available during text entry.  
- Theme support — light and dark themes switchable at any time via a toggle.  
- Tray and Escape behavior — the client can minimize to the system tray on close or when pressing Escape.  
- Localization — both projects include French and English translations.


### How to Run

- Clone the repository
- Open in Visual Studio 2022
- Build and run the solution to test the two projects in local connection.

### Download
Go to the [Releases](../../releases) section to download a ZIP archive containing the compiled executables (compatible with x64 systems running Windows 7 or later).
