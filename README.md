## WPF Chat app and server
- Uses MVVM model.
- The client can run on localhost if the IP address of the server is left blank. 
- Both server and client create network packets, using a packet builder. It inserts an opcode at the beginning, so that the package reader can determine its type. 
- Includes a list of connected users, which updates automatically when someone logs in or out.
- The client remembers the last IP address it connected to.

<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/master/WPF-chat-server-main-window-screenshot.jpg" width="500" alt="screenshot of chat server app" >
</p>
