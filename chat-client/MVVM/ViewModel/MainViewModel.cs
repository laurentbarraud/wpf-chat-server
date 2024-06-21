/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.4</version>
/// <date>June 21th, 2024</date>


using chat_client.MVVM.Model;
using chat_client.Net;
using System.Collections.ObjectModel;
using System.Windows;


namespace chat_client.MVVM.ViewModel
{
    public class MainViewModel
    {
        // Represents a dynamic data collection that provides notification
        // when items are added or removed, or when the full list is refreshed.
        public ObservableCollection<UserModel> Users { get; set; }
        public ObservableCollection<string> Messages { get; set; }

        // What the user type in the first textbox on top left of
        // the MainWindow in View gets stored in this property
        // (binded in xaml file)
        public static string Username { get; set; }

        // What the user type in the second textbox on top left of
        // the MainWindow in View gets stored in this property
        // (binded in xaml file)
        public static string IPAddressOfServer { get; set; }

        // What the user type in the textbox on bottom right
        // of the MainWindow in View gets stored in this property
        // (binded in xaml file)
        public static string Message { get; set; }

        public static Server _server;

        public MainViewModel()
        {
            ObservableCollection<UserModel> Users = new ObservableCollection<UserModel>();
            ObservableCollection<string> Messages = new ObservableCollection<string>();
            _server = new Server();
            _server.connectedEvent += UserConnected;
            _server.msgReceivedEvent += MessageReceived;
            _server.userDisconnectEvent += RemoveUser;
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
            
            if (msg.EndsWith("disconnected!"))
            {
                Application.Current.Dispatcher.Invoke(() => Messages.Add("[Server]: " + msg));
            } 
            
            else
            {
                Application.Current.Dispatcher.Invoke(() => Messages.Add(msg));
            }
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
