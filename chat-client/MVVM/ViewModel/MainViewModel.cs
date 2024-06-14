using chat_client.MVVM.Core;
using chat_client.MVVM.Model;
using chat_client.Net;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Xml.Linq;

namespace chat_client.MVVM.ViewModel
{
    class MainViewModel
    {
        // Represents a dynamic data collection that provides notification
        // when items are added or removed, or when the full list is refreshed.
        public ObservableCollection<UserModel> Users { get; set; }
        public ObservableCollection<string> Messages { get; set; }

        // The RelayCommand is a ICommand implementation that can expose
        // a method or delegate to the view.These types act as a way
        // to bind commands between the viewmodel and UI elements.
        public RelayCommand ConnectToServerCommand { get; set; }
        public RelayCommand SendMessageCommand { get; set; }

        // What the user type in the textbox on top left of
        // the MainWindow in View gets stored in this property
        // (binded in xaml file)
        public string Username { get; set; }

        // What the user type in the textbox on bottom right
        // of the MainWindow in View gets stored in this property
        // (binded in xaml file)
        public string Message { get; set; }

        private Server _server;

        public MainViewModel()
        {
            Users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<string>();
            _server = new Server();
            _server.connectedEvent += UserConnected;
            _server.msgReceivedEvent += MessageReceived;
            _server.userDisconnectEvent += RemoveUser;

            // These commands will be able to run only if the binded property is not empty.
            ConnectToServerCommand = new RelayCommand(o => _server.ConnectToServer(Username), o => !string.IsNullOrEmpty(Username));
            SendMessageCommand = new RelayCommand(o => _server.SendMessageToServer(Message), o => !string.IsNullOrEmpty(Message));
        }

        private void RemoveUser()
        {
            // This is the first thing sent when a user disconnects
            var uid = _server.PacketReader.ReadMessage();
            var user = Users.Where(x => x.UID == uid).FirstOrDefault();
            
            // Removes the user from the collection
            Application.Current.Dispatcher.Invoke(() => Users.Remove(user));

        }

        /// <summary>
        /// Reads the data incoming
        /// </summary>
        private void MessageReceived()
        {
            var msg = _server.PacketReader.ReadMessage();
            Application.Current.Dispatcher.Invoke(() => Messages.Add($"{Username} says: " + msg));
        }

        private void UserConnected()
        {
            var user = new UserModel
            {
                Username = _server.PacketReader.ReadMessage(),
                UID = _server.PacketReader.ReadMessage(), 
            };

            // If the users collection doesn't
            // contain any user that already has that UID
            if (!Users.Any(x => x.UID == user.UID))
            {
                // We add data to the collection
                Application.Current.Dispatcher.Invoke(() => Users.Add(user));
            }

        }


    }
}
