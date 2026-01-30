## WPF Chat App
A real-time WPF chat client and console server in C#, featuring TcpClient networking and a custom packet builder and reader.

[![Release](https://img.shields.io/badge/release-stable-1B4636)](https://github.com/laurentbarraud/wpf-chat-server/releases)
[![GitHub release downloads](https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/v0.9/total?color=88aacc&style=flat)](https://github.com/laurentbarraud/wpf-chat-server/releases/tag/v0.9)

<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/refs/heads/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="modern WPF chat app client screenshot" >
</p>

### Features
- 👥 Real‑time user list — the client shows connected users and the list updates automatically on login/logout
- 😀 UTF‑8 message encoding — an emoji toolbar is available during text entry
- 🔌 Configurable TCP port — the client can choose the TCP port before connecting; the server accepts a custom bind port at startup  
- 🏠 Local mode — the client will run locally if no IP address is provided-
- 🪟 Tray and Escape behavior — the client can minimize to the system tray on close, reduce or when pressing Escape  
- 🎨 Theme support — light and dark themes switchable at any time via a toggle  
- 🌐 Fully localized in French and English 

### Development Setup
*(Unstable build — it is recommended to download the latest release instead)*

- Open the '.sln' file in Visual Studio 2022  
- Build the solution with Ctrl+Shift+B  
- Run with debugging (F5) to test both projects using local connection
- Launch additional clients as needed to simulate 2, 3, or more connected users

### Download
Go to the [Releases](../../releases) section.
Provided as a ZIP archive with compiled executables, compatible with Windows 7 and above (x64).
