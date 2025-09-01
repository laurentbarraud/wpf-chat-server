/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.6</version>
/// <date>September 1st, 2025</date>


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

        public static bool IsConnectedToServer { get; set; }

        public MainViewModel()
        {
            Users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<string>();
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
        /// Reads the data incoming and handles disconnect command gracefully.
        /// </summary>
        private void MessageReceived()
        {
            var msg = _server.PacketReader.ReadMessage();

            // Checks for disconnect command from server
            if (msg == "/disconnect")
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    // Gets reference to MainWindow and ViewModel
                    var mainWindow = Application.Current.MainWindow as MainWindow;
                    if (mainWindow == null || mainWindow.ViewModel == null)
                        return;

                    var viewModel = mainWindow.ViewModel;

                    // Creates a timer to delay UI reset
                    var timer = new System.Timers.Timer(2000)
                    {
                        AutoReset = false // Fire only once
                    };

                    timer.Elapsed += (s, e) =>
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            // Resets UI state
                            mainWindow.cmdConnect.Content = "_Connect";
                            mainWindow.txtUsername.IsEnabled = true;
                            mainWindow.txtIPAddress.IsEnabled = true;

                            viewModel.Users.Clear();
                            viewModel.Messages.Clear();

                            mainWindow.Title = "WPF Chat Server";
                            mainWindow.spnCenter.Visibility = Visibility.Hidden;
                            MainViewModel.IsConnectedToServer = false;

                            // Closes socket if still open
                            _server.DisconnectFromServer();
                        });
                    };

                    timer.Start();
                });

                return;
            }

            // Normal message
            Application.Current.Dispatcher.Invoke(() => Messages.Add(msg));
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
