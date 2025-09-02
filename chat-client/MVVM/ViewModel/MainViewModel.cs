/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.7</version>
/// <date>September 3rd, 2025</date>

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
            Users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<string>();
            _server = new Server();
            _server.connectedEvent += UserConnected;
            _server.msgReceivedEvent += MessageReceived;
            _server.userDisconnectEvent += RemoveUser;
        }

        /// <summary>
        /// Attempts to connect the client to the server using the provided username and IP address.
        /// Updates the UI accordingly and saves the last used IP.
        /// </summary>
        public void Connect()
        {
            // Abort if username is missing
            if (string.IsNullOrEmpty(Username))
                return;
            
            try
            {
                // Disable input fields during connection attempt
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        mainWindow.txtUsername.IsEnabled = false;
                        mainWindow.txtIPAddress.IsEnabled = false;
                    }
                });

                // Attempt to connect to the server
                bool connected = _server.ConnectToServer(Username, IPAddressOfServer);
                if (!connected)
                    throw new Exception("Connection failed.");

                // Update UI to reflect connected state
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        mainWindow.Title += " - Connected";
                        mainWindow.cmdConnectDisconnect.Content = "_Disconnect";
                        mainWindow.spnCenter.Visibility = Visibility.Visible;
                        mainWindow.cmdPortSetting.IsEnabled = false;
                    }
                });

                // Save last used IP for future sessions
                chat_client.Properties.Settings.Default.LastIPAddressUsed = IPAddressOfServer;
                chat_client.Properties.Settings.Default.Save();
            }
            catch (Exception)
            {
                // Handle connection failure and reset UI
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        MessageBox.Show("The server is unreachable or has refused the connection.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        ReinitializeUI();
                    }
                });
            }
        }


        /// <summary>
        /// Connect or disconnect the client, depending on the connection status
        /// </summary>
        public void ConnectDisconnect()
        {
            if (_server.IsConnected)
            {
                Disconnect();
            }
            else
            {
                Connect();
            }
        }

        /// <summary>
        /// Disconnects the client from the server and resets the UI state.
        /// </summary>
        public void Disconnect()
        {
            try
            {
                // Attempt to close the connection to the server
                _server.DisconnectFromServer();

                // Reset the UI and clear user/message data
                ReinitializeUI();
            }
            catch (Exception ex)
            {
                // Display an error message if disconnection fails
                MessageBox.Show($"Error while disconnecting: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Returns the current port number stored in application settings.
        /// </summary>
        public int GetCurrentPort()
        {
            return chat_client.Properties.Settings.Default.PortNumber;
        }

        /// <summary>
        /// Validates and saves the port number if it's within the allowed range.
        /// </summary>
        public bool TrySavePort(int chosenPort)
        {
            if (chosenPort >= 1000 && chosenPort <= 65535)
            {
                chat_client.Properties.Settings.Default.PortNumber = chosenPort;
                chat_client.Properties.Settings.Default.Save();
                return true;
            }

            return false;
        }

        /// <summary>
        /// Clears user and message data and restores the UI to its initial state.
        /// </summary>
        public void ReinitializeUI()
        {
            // Clear the collections bound to the UI
            Users.Clear();
            Messages.Clear();

            // Update UI elements on the main thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow)
                {
                    // Reset the connect/disconnect button
                    mainWindow.cmdConnectDisconnect.Content = "_Connect";

                    // Re-enable input fields
                    mainWindow.txtUsername.IsEnabled = true;
                    mainWindow.txtIPAddress.IsEnabled = true;

                    // Reset window title
                    mainWindow.Title = "WPF Chat Server";

                    // Hide the central panel
                    mainWindow.spnCenter.Visibility = Visibility.Hidden;

                    // Enable the port setting button
                    mainWindow.cmdPortSetting.IsEnabled = true;
                }
            });
        }

        /// <summary>
        /// Reads the data incoming and handles disconnect command gracefully.
        /// </summary>
        /// <summary>
        /// Handles incoming messages from the server. If a disconnect command is received,
        /// the UI is reset after a short delay. Otherwise, the message is added to the chat.
        /// </summary>
        private void MessageReceived()
        {
            var msg = _server.PacketReader.ReadMessage();

            // Check for server-issued disconnect command
            if (msg == "/disconnect")
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    // Get reference to MainWindow and its ViewModel
                    if (Application.Current.MainWindow is MainWindow mainWindow && mainWindow.ViewModel != null)
                    {
                        var viewModel = mainWindow.ViewModel;

                        // Create a timer to delay UI reset
                        var timer = new System.Timers.Timer(2000)
                        {
                            AutoReset = false // Trigger only once
                        };

                        timer.Elapsed += (s, e) =>
                        {
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                // Reset UI and clear data
                                viewModel.ReinitializeUI();

                                // Ensure socket is closed
                                _server.DisconnectFromServer();
                            });
                        };

                        timer.Start();
                    }
                });

                return;
            }

            // Normal message — add to chat
            Application.Current.Dispatcher.Invoke(() => Messages.Add(msg));
        }


        private void RemoveUser()
        {
            // This is the first thing sent when a user disconnects
            var uid = _server.PacketReader.ReadMessage();
            var user = Users.Where(x => x.UID == uid).FirstOrDefault();

            // Removes the user from the collection
            Application.Current.Dispatcher.Invoke(() => Users.Remove(user));

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
