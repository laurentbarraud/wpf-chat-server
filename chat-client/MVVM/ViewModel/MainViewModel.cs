using chat_client.MVVM.Core;
using chat_client.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace chat_client.MVVM.ViewModel
{
    class MainViewModel
    {
        public RelayCommand ConnectToServerCommand { get; set; }

        // What the user type in the textbox on top left of
        // the MainWindow in View gets stored in this property
        public string Username { get; set; }

        private Server _server;

        public MainViewModel()
        {
            _server = new Server();

            // This command will be able to run only if the Username
            // property is not empty
            ConnectToServerCommand = new RelayCommand(o => _server.ConnectToServer(Username), o => !string.IsNullOrEmpty(Username));
        }
    }
}
