### WPF Chat app and server
![Release](https://img.shields.io/badge/release-stable-1B4636)
![GitHub release downloads](https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/v0.4/total?color=88aacc&style=flat)

- Uses MVVM model.
- The client can run on localhost if the IP address of the server is left blank. 
- Both server and client create network packets, using a packet builder. It inserts an opcode at the beginning, so that the package reader can determine its type. 
- Includes a list of connected users, which updates automatically when someone logs in or out.
- The client remembers the last IP address it connected to.

<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="screenshot of chat server app" >
</p>

### How to Run

- Clone the repository
- Open in Visual Studio 2022
- Build and run the solution

Or go to the Release section to download a zip archive, containing the compiled executable (for x64 systems, starting from Windows 7 and upwards)
