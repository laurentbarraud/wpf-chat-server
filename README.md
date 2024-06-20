## WPF Chat app and server
- Uses MVVM model.
- The client can run on localhost if the IP address of the server is left blank. 
- Both server and client create network packets, using a packet builder. It inserts an opcode at the beginning, so that the package reader can determine its type. 
- Includes a list of connected users, which updates automatically when someone logs in or out.
- The last IP address that the client successfully connected to is stored in the app for convenient use. 

<p align="center">
<img src="https://raw.githubusercontent.com/laurentbarraud/wpf-chat-server/master/WPF-chat-server-screenshot.jpg" width="500" alt="screenshot of chat server app" >
</p>
