using chat_client.MVVM.Core;
using chat_client.MVVM.Model;
using chat_client.Net;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace chat_client.MVVM.ViewModel
{
    class MainViewModel
    {
        // Represents a dynamic data collection that provides notification
        // when items are added or removed, or when the full list is refreshed.
        public ObservableCollection<UserModel> Users { get; set; }

        public RelayCommand ConnectToServerCommand { get; set; }

        // What the user type in the textbox on top left of
        // the MainWindow in View gets stored in this property
        public string Username { get; set; }

        private Server _server;

        public MainViewModel()
        {
            Users = new ObservableCollection<UserModel>();
            _server = new Server();
            _server.connectedEvent += UserConnected;

            // This command will be able to run only if the Username
            // property is not empty
            ConnectToServerCommand = new RelayCommand(o => _server.ConnectToServer(Username), o => !string.IsNullOrEmpty(Username));
        }

        private void UserConnected()
        {
            var user = new UserModel
            {
                Username = _server.PacketReader.ReadMessage(),
                UID = _server.PacketReader.ReadMessage(),
            };


        }
    }
}
