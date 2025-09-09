/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 8th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.Net;
using chat_client.Net.IO;
using System;
using System.Collections.ObjectModel;
using System.Reflection.Metadata;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.ComponentModel;


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
        // (binded in xaml file).
        public static string Username { get; set; }

        // What the user type in the second textbox on top left of
        // the MainWindow in View gets stored in this property
        // (binded in xaml file)
        public static string IPAddressOfServer { get; set; }

        // What the user type in the textbox on bottom right
        // of the MainWindow in View gets stored in this property
        // (binded in xaml file).
        public static string Message { get; set; }

        public static Server _server;

        // Declaring the list as public ensures it can be resolved by WPF's binding system,
        // assuming the containing object is set as the DataContext.
        public List<string> EmojiList { get; } = new()
        {
            "😀", "👍", "🙏", "😅", "😂", "🤣", "😉", "😎",
            "😁", "😇", "🤨", "😏", "🕒", "📌", "❤️", "👀",
            "🤷", "🤝", "🔥", "⚠️", "💤", "📞", "🧠", "🛠️",
            "🥳", "😴", "😲", "😘", "👌", "💪", "🙈", "🤐",
            "😷", "👋", "🍺", "🍻", "🍾", "☀️", "⭐",
            "🌧️", "🔥", "✨"
        };

        // Exposes the current encryption setting (UseEncryption) as a read-only property.
        // Uses expression-bodied syntax (=>) for clarity and ensures the value is always up-to-date.
        public bool IsEncryptionEnabled => chat_client.Properties.Settings.Default.UseEncryption;

        public MainViewModel()
        {
            Users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<string>();
            _server = new Server();
            _server.connectedEvent += UserConnected;
            _server.msgReceivedEvent += MessageReceived;
            _server.userDisconnectEvent += UserDisconnected;
        }

        /// <summary>
        /// Attempts to connect the client to the server using the provided username and IP address.
        /// Updates the UI accordingly and saves the last used IP.
        /// </summary>
        public void Connect()
        {
            // Abort if username is missing or format is invalid
            if (string.IsNullOrWhiteSpace(Username) || !Regex.IsMatch(Username, @"^[a-zA-Z][a-zA-Z0-9_-]*$"))
            {
                // Highlight the textbox in crimson to indicate invalid input
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        mainWindow.txtUsername.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#DC143C"));
                        mainWindow.txtUsername.Focus();
                    }
                });

                return;
            }

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

                        // If encryption is enabled, send public key to server
                        if (chat_client.Properties.Settings.Default.UseEncryption)
                        {
                            // Get the public key in Base64 format
                            string publicKeyBase64 = EncryptionHelper.GetPublicKeyBase64();

                            // Send the public key to the server using opcode 6 (example)
                            var keyPacket = new PacketBuilder();
                            keyPacket.WriteOpCode(6); // Define opcode 6 for public key exchange
                            keyPacket.WriteMessage(publicKeyBase64);

                            // Send the packet using the server's raw packet method,
                            // which is designed for binary payloads like key exchange.
                            _server.SendRawPacket(keyPacket.GetPacketBytes());
                        }

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
        public static int GetCurrentPort()
        {
            return chat_client.Properties.Settings.Default.CustomPortNumber;
        }

        /// <summary>
        /// Validates and saves the port number if it's within the allowed range.
        /// </summary>
        public static bool TrySavePort(int chosenPort)
        {
            if (chosenPort >= 1000 && chosenPort <= 65535)
            {
                chat_client.Properties.Settings.Default.CustomPortNumber = chosenPort;
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
            // Clears the collections bound to the UI
            Users.Clear();
            Messages.Clear();

            // Updates UI elements on the main thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow)
                {
                    mainWindow.cmdConnectDisconnect.Content = "_Connect";

                    mainWindow.txtUsername.IsEnabled = true;
                    mainWindow.txtIPAddress.IsEnabled = true;
                    mainWindow.Title = "WPF Chat Server";

                    // Hides the central panel
                    mainWindow.spnCenter.Visibility = Visibility.Hidden;
                }
            });
        }

        /// <summary>
        /// Reads the data incoming and handles disconnect command gracefully.
        /// Handles incoming messages from the server. If a disconnect command is received,
        /// the UI is reset after a short delay. Otherwise, the message is optionally decrypted
        /// (if encryption is enabled) and added to the chat.
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

            // Checks if the incoming message contains the encryption marker
            if (msg.Contains("[ENC]"))
            {
                try
                {
                    // Extracts the sender's prefix before the encryption marker
                    int markerIndex = msg.IndexOf("[ENC]");
                    string senderPrefix = msg.Substring(0, markerIndex).Trim();

                    // Extracts the encrypted payload after the marker
                    string encryptedPayload = msg.Substring(markerIndex + "[ENC]".Length).Trim();

                    // Cleans up any invisible or invalid characters that may break decryption
                    encryptedPayload = encryptedPayload
                        .Replace("\0", "")
                        .Replace("\r", "")
                        .Replace("\n", "");

                    // Attempts to decrypt the payload
                    string decryptedContent = EncryptionHelper.DecryptMessage(encryptedPayload);

                    // Reconstructs the full message with sender and decrypted content
                    msg = $"{senderPrefix} {decryptedContent}";
                }
                catch (Exception ex)
                {
                    // Replaces the message with a failure notice
                    msg = "[Decryption failed]";
                }
            }

        // Normal message — add to chat
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
                // Executes UI bound actions on the main application thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Users.Add(user);
                    
                    // Avoids to be notified of who is connected at login time (user sees it in the list of users on left)
                    if (Message != null)
                    {
                        Messages.Add($"# - {user.Username} has connected. #");
                    }
                });
            }
        }

        private void UserDisconnected()
        {
            // This is the first thing sent when a user disconnects
            var uid = _server.PacketReader.ReadMessage();

            // Executes UI bound actions on the main application thread
            var user = Users.FirstOrDefault(x => x.UID == uid);

            // Ensures user exists to avoid NullReferenceException
            if (user != null)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Users.Remove(user);
                    Messages.Add($"# - {user.Username} has disconnected. #");
                });
            }
        }
    }
}
