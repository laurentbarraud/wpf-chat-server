/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 12th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.Net;
using chat_client.Net.IO;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.StartPanel;



namespace chat_client.MVVM.ViewModel
{
    public class MainViewModel : INotifyPropertyChanged
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

        public UserModel LocalUser { get; set; }


        public Server _server = new Server();

        public Server Server => _server;

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

        /// <summary>
        /// Represents the currently selected user in the chat interface.
        /// Used to determine the intended recipient of outgoing messages,
        /// especially when encryption is enabled and the correct public key must be applied.
        /// </summary>
        public UserModel SelectedUser { get; set; }

        /// <summary>
        /// Static UID used to identify system-originated messages such as server shutdown or administrative commands.
        /// This allows clients to verify message authenticity and prevent spoofed disconnects or control signals.
        /// </summary>
        public static readonly Guid SystemUID = Guid.Parse("00000000-0000-0000-0000-000000000001");

        private bool _isConnected;

        /// <summary>
        /// Indicates whether the client is currently connected to the server.
        /// Triggers a property change notification to update any bound UI elements when the connection state changes.
        /// </summary>
        public bool IsConnected
        {
            get => _isConnected;
            set
            {
                if (_isConnected != value)
                {
                    _isConnected = value;

                    // Warns the interface that the value has changed
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Event triggered when a property value changes, used to notify bound UI elements in data-binding scenarios.
        /// Implements the INotifyPropertyChanged interface to support reactive updates in WPF.
        /// </summary>
        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <summary>
        /// Stores public keys of other connected users, indexed by their UID.
        /// Used for encrypting messages to specific recipients.
        /// </summary>
        public Dictionary<string, string> KnownPublicKeys { get; } = new();


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
                LocalUser = new UserModel
                {
                    Username = Username.Trim(),
                };

                // Attempt to connect to the server
                IsConnected = _server.ConnectToServer(Username, IPAddressOfServer);
                if (!IsConnected)
                    throw new Exception(LocalizationManager.GetString("ConnectionFailed"));

                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        // Disable input fields
                        mainWindow.txtUsername.IsEnabled = false;
                        mainWindow.txtIPAddress.IsEnabled = false;

                        // Update localized UI
                        LocalizationManager.UpdateLocalizedUI();

                        // Update title and visibility
                        mainWindow.Title += " - " + LocalizationManager.GetString("Connected");
                        mainWindow.spnCenter.Visibility = Visibility.Visible;
                    }
                });


                // Save last used IP for future sessions
                chat_client.Properties.Settings.Default.LastIPAddressUsed = IPAddressOfServer;
                chat_client.Properties.Settings.Default.Save();
            }
            catch (Exception)
            {
                // Handles connection failure and reset UI
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        MessageBox.Show(LocalizationManager.GetString("ServerUnreachable"), LocalizationManager.GetString("Error"), MessageBoxButton.OK, MessageBoxImage.Error);
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
                MessageBox.Show(LocalizationManager.GetString("ErrorWhileDisconnecting") + ex.Message, LocalizationManager.GetString("Error"), MessageBoxButton.OK, MessageBoxImage.Error);
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
        /// Initializes encryption if enabled in application settings.
        /// Generates the public key, stores it in LocalUser, sends it to the server,
        /// and updates the encryption status icon in the UI.
        /// </summary>
        public void InitializeEncryptionIfEnabled()
        {
            // Abort if encryption is disabled or required objects are missing
            if (!Properties.Settings.Default.UseEncryption || LocalUser == null || Server == null)
                return;

            // Generate and store public key
            LocalUser.PublicKeyBase64 = EncryptionHelper.GetPublicKeyBase64();

            // Send public key to server
            Server.SendPublicKeyToServer(
                LocalUser.UID,
                LocalUser.Username,
                LocalUser.PublicKeyBase64
            );

            // Update encryption icon and trigger animation
            (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon();
        }

        /// <summary>
        /// Handles incoming messages from the server.
        /// Supports encrypted messages, system-issued disconnect commands, and standard chat messages.
        /// </summary>
        private void MessageReceived()
        {
            // Reads the message content and sender UID from the incoming packet
            string rawMessage = _server.PacketReader.ReadMessage(); // May contain plain text or [ENC] marker
            string senderUID = _server.PacketReader.ReadMessage();  // UID of the message sender

            // Checks for server-issued disconnect command
            // Only triggers disconnect if the message comes from the system UID to prevent spoofing
            if (rawMessage == "/disconnect" && senderUID == SystemUID.ToString())
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
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
                                // Reset UI and disconnect from server
                                viewModel.ReinitializeUI();
                                _server.DisconnectFromServer();
                            });
                        };

                        timer.Start();
                    }
                });

                return;
            }

            string displayName = Users.FirstOrDefault(u => u.UID == senderUID)?.Username ?? senderUID;

            // Checks if the incoming message contains the encryption marker
            if (rawMessage.Contains("[ENC]"))
            {
                // Predeclare decrypted content to ensure visibility in both try and catch blocks
                string decryptedContent = string.Empty;

                try
                {
                    // Locate the encryption marker and extract the encrypted payload
                    int markerIndex = rawMessage.IndexOf("[ENC]");
                    string encryptedPayload = rawMessage.Substring(markerIndex + "[ENC]".Length).Trim();

                    // Cleans up any invisible or invalid characters that may break decryption
                    encryptedPayload = encryptedPayload
                        .Replace("\0", "")
                        .Replace("\r", "")
                        .Replace("\n", "");

                    // Attempts to decrypt the payload using the local private key
                    decryptedContent = EncryptionHelper.DecryptMessage(encryptedPayload);

                    // Reconstructs the full message with sender display name and decrypted content
                    rawMessage = $"{displayName}: {decryptedContent}";
                }
                catch (Exception)
                {
                    // Replaces the message with a localized failure notice if decryption fails
                    rawMessage = $"{displayName}: {LocalizationManager.GetString("DecryptionFailed")}";
                }
            }
            else
            {
                // Reconstructs the full message with sender display name and plain text content
                rawMessage = $"{displayName}: {rawMessage}";
            }

            // Adds the final message to the chat interface
            Application.Current.Dispatcher.Invoke(() => Messages.Add(rawMessage));

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
                    mainWindow.cmdConnectDisconnect.Content = LocalizationManager.GetString("ConnectButton");

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
        private void UserConnected()
        {
            var user = new UserModel
            {
                Username = _server.PacketReader.ReadMessage(),
                UID = _server.PacketReader.ReadMessage(),
            };

            // Checks whether the user is already present in the Users collection,
            // by verifying that no existing user has the same UID.
            // Uses LINQ's .Any() to efficiently scan the collection.
            // The! in front means that no existing user has this UID
            // So we add the new user only if he is not already in the list
            // This prevents duplicate entries when multiple connection events are received.


            if (!Users.Any(x => x.UID == user.UID))
            {
                // Executes UI bound actions on the main application thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Users.Add(user);
                    
                    // Avoids to be notified of who is connected at login time (user sees it in the list of users on left)
                    if (Message != null)
                    {
                        Messages.Add("# - " + user.Username + " " + LocalizationManager.GetString("HasConnected") + ". #");
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
                    Messages.Add("# - " + user.Username + " " + LocalizationManager.GetString("HasDisconnected") + ". #");
                });
            }
        }
    }
}
