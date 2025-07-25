### WPF Chat app and server 

![Release](https://img.shields.io/badge/release-stable-1B4636)
![GitHub release downloads](https://img.shields.io/github/downloads/laurentbarraud/wpf-chat-server/v0.4/total?color=88aacc&style=flat)

<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="screenshot of chat server app" >
</p>

- The client can run locally if no IP address is provided.
- Both the server and client use a custom packet builder that adds an opcode to each packet, allowing the receiver to identify its type.
- The application includes a real-time list of connected users, which updates automatically when users log in or out.
- The client also remembers the last IP address it successfully connected to, making reconnections faster and more convenient.

### How to Run

- Clone the repository
- Open in Visual Studio 2022
- Build and run the solution

Or go to the Release section to download a zip archive, containing the compiled executable (for x64 systems, starting from Windows 7 and upwards)
