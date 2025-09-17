/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 16th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.MVVM.View;
using chat_client.Net;
using chat_client.Net.IO;
using Hardcodet.Wpf.TaskbarNotification;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;



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
        /// Used to control UI visibility, trigger encryption setup, and manage connection-dependent features.
        /// Automatically notifies bound UI elements when the state changes.
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

        /// <summary>
        /// Tracks which users have already received our public RSA key.
        /// Used to prevent redundant key transmissions and ensure mutual encryption setup.
        /// </summary>
        private readonly HashSet<string> _uidsKeySentTo = new();

        /// <summary>
        /// Checks whether the local user has already sent their public key to the specified UID.
        /// </summary>
        /// <param name="uid">Unique identifier of the remote user.</param>
        /// <returns>True if the key has already been sent; otherwise, false.</returns>
        private bool HasSentKeyTo(string uid) => _uidsKeySentTo.Contains(uid);

        /// <summary>
        /// Marks the specified UID as having received our public RSA key.
        /// Prevents duplicate transmissions during key exchange.
        /// </summary>
        /// <param name="uid">Unique identifier of the remote user.</param>
        private void MarkKeyAsSentTo(string uid) => _uidsKeySentTo.Add(uid);

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
        /// Determines whether all connected users (excluding the local user)
        /// have successfully exchanged their public RSA keys.
        /// Returns true only if encryption is enabled and every other user has a known public key.
        /// Handles edge cases such as solo client sessions and ensures accurate UI feedback.
        /// </summary>
        /// <returns>True if all required keys are received; otherwise, false.</returns>
        public bool AreAllKeysReceived()
        {
            // Encryption must be explicitly enabled to evaluate readiness
            if (!IsEncryptionEnabled)
                return false;

            // Validates user list
            if (Users == null || Users.Count == 0)
                return false;

            // If only the local user is present, encryption is trivially ready
            if (Users.Count == 1 && Users[0].UID == LocalUser?.UID)
                return true;

            // Iterates through all connected users except the local one
            foreach (var user in Users)
            {
                // Skips self
                if (user.UID == LocalUser?.UID)
                    continue;

                // If any user lacks a known public key, encryption is incomplete
                if (!KnownPublicKeys.ContainsKey(user.UID))
                    return false;
            }

            // All required keys are present
            return true;
        }


        /// <summary>
        /// Attempts to connect the client to the server.
        /// Initializes LocalUser with Username and a unique UID for key exchange.
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
                    UID = Guid.NewGuid().ToString() // Ajout d’un UID unique ici
                };

                IsConnected = _server.ConnectToServer(Username, IPAddressOfServer); // Returns a bool
                if (!IsConnected)
                    throw new Exception(LocalizationManager.GetString("ConnectionFailed"));

                // If encryption is enabled in settings, initialize and send public key
                if (Properties.Settings.Default.UseEncryption)
                {
                    InitializeEncryptionIfEnabled();
                }

                // Updates UI to reflect connected state
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        mainWindow.Title += " - Connected";
                        mainWindow.cmdConnectDisconnect.Content = "_Disconnect";
                        mainWindow.spnCenter.Visibility = Visibility.Visible;
                    }
                });

                chat_client.Properties.Settings.Default.LastIPAddressUsed = IPAddressOfServer;
                chat_client.Properties.Settings.Default.Save();
            }
            catch (Exception)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mw)
                    {
                        MessageBox.Show(LocalizationManager.GetString("ServerUnreachable"),
                                        LocalizationManager.GetString("Error"),
                                        MessageBoxButton.OK,
                                        MessageBoxImage.Error);
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
        /// Attempts to initialize encryption when the toggle is activated.
        /// Generates a fresh 2048-bit RSA key pair, encodes the public and private keys in Base64,
        /// stores them locally, and sends the public key to the server.
        /// Displays a localized error message on send failure.
        /// Idempotent: repeated calls produce the same result without duplicates or crashes.
        /// Skips initialization if the public key is already present.
        /// </summary>
        public bool InitializeEncryptionIfEnabled()
        {
            // Skips initialization if user is not defined or encryption is already initialized
            if (LocalUser == null || !string.IsNullOrEmpty(LocalUser.PublicKeyBase64))
                return false;

            try
            {
                // Generates a new RSA key pair (2048-bit)
                using var rsa = new RSACryptoServiceProvider(2048);

                // Exports public and private keys as XML strings
                string publicKeyXml = rsa.ToXmlString(false); // public only
                string privateKeyXml = rsa.ToXmlString(true); // includes private parameters

                // Encodes keys in Base64 for safe transport and storage
                string publicKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyXml));
                string privateKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyXml));

                // Stores keys in the local user model
                LocalUser.PublicKeyBase64 = publicKeyBase64;
                LocalUser.PrivateKeyBase64 = privateKeyBase64;

                // Injects private key into EncryptionHelper for decryption readiness
                // This guarantees that privateKey is properly initialized before any decryption attempt
                EncryptionHelper.SetPrivateKey(privateKeyBase64);

                // Attempts to send the public key to the server
                bool sent = Server.SendPublicKeyToServer(LocalUser.UID, publicKeyBase64);
                if (!sent)
                {
                    // Shows localized error and rollback encryption setting
                    MessageBox.Show(
                        LocalizationManager.GetString("SendingClientsPublicRSAKeyToTheServerFailed"),
                        LocalizationManager.GetString("Error"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);

                    Properties.Settings.Default.UseEncryption = false;
                    Properties.Settings.Default.Save();
                    return false;
                }

                // Marks encryption as active in settings
                Properties.Settings.Default.UseEncryption = true;
                Properties.Settings.Default.Save();
                return true;
            }
            catch
            {
                // Rollbacks encryption setting on failure
                Properties.Settings.Default.UseEncryption = false;
                Properties.Settings.Default.Save();
                return false;
            }
        }

        /// <summary>
        /// Handles incoming messages from the server.
        /// If encryption is disabled, displays the message in plain text.
        /// If encryption is enabled, attempts to decrypt the message; if decryption fails, displays a placeholder.
        /// Also handles system-issued disconnect commands and updates the UI accordingly.
        /// </summary>
        private void MessageReceived()
        {
            // Reads the message content and sender UID from the incoming packet
            string rawMessage = _server.PacketReader.ReadMessage(); // May contain plain text or [ENC] marker
            string senderUID = _server.PacketReader.ReadMessage();  // UID of the message sender

            // Handles system-issued disconnect command (only if sent by system UID)
            if (rawMessage == "/disconnect" && senderUID == SystemUID.ToString())
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow && mainWindow.ViewModel is MainViewModel viewModel)
                    {
                        // Delays UI reset to allow user to read disconnect notice
                        var timer = new System.Timers.Timer(2000)
                        {
                            AutoReset = false
                        };

                        timer.Elapsed += (s, e) =>
                        {
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                viewModel.ReinitializeUI();
                                _server.DisconnectFromServer();
                            });
                        };

                        timer.Start();
                    }
                });

                return;
            }

            // Resolves sender display name from UID
            string displayName = Users.FirstOrDefault(u => u.UID == senderUID)?.Username ?? senderUID;

            // Checks if the message is encrypted
            if (rawMessage.Contains("[ENC]"))
            {
                string decryptedContent = string.Empty;

                try
                {
                    // Extracts encrypted payload after the [ENC] marker
                    int markerIndex = rawMessage.IndexOf("[ENC]");
                    string encryptedPayload = rawMessage.Substring(markerIndex + "[ENC]".Length).Trim();

                    // Cleans up any invisible or invalid characters
                    encryptedPayload = encryptedPayload
                        .Replace("\0", "")
                        .Replace("\r", "")
                        .Replace("\n", "");

                    // Attempts to decrypt using the local private key
                    decryptedContent = TryDecryptMessage(encryptedPayload);

                    // Formats the decrypted message with sender name
                    rawMessage = $"{displayName}: {decryptedContent}";
                }
                catch (Exception)
                {
                    // If decryption fails, shows a localized placeholder
                    rawMessage = $"{displayName}: {LocalizationManager.GetString("DecryptionFailed")}";
                }
            }
            else
            {
                // Formats plain text message with sender name
                rawMessage = $"{displayName}: {rawMessage}";
            }

            // Adds the final message to the chat interface
            Application.Current.Dispatcher.Invoke(() => Messages.Add(rawMessage));
        }


        /// <summary>
        /// Handles the reception of a public RSA key from another connected client.
        /// Stores the received key locally and, if encryption is enabled, sends our own key back to ensure mutual encryption.
        /// This method supports bidirectional key exchange and updates the encryption status icon accordingly.
        /// </summary>
        /// <param name="uid">The unique identifier of the sender.</param>
        /// <param name="publicKeyBase64">The sender's public RSA key encoded in Base64.</param>
        public void ReceivePublicKey(string uid, string publicKeyBase64)
        {
            // Validate input: ignore empty UID or malformed key
            if (string.IsNullOrEmpty(uid) || string.IsNullOrEmpty(publicKeyBase64))
                return;

            // Store the received public key in the dictionary for future encryption
            KnownPublicKeys[uid] = publicKeyBase64;
            Console.WriteLine($"[INFO] Stored public key for UID: {uid}");

            // If encryption is enabled and we haven't yet sent our key to this UID
            if (IsEncryptionEnabled && LocalUser?.UID != null && !HasSentKeyTo(uid))
            {
                // Ensure our own public key is available before sending
                if (!string.IsNullOrEmpty(LocalUser.PublicKeyBase64))
                {
                    // Send our public key to the client who just sent theirs
                    Server.SendPublicKeyToServer(uid, LocalUser.PublicKeyBase64);

                    // Mark that we've sent our key to this UID to avoid duplicate transmission
                    MarkKeyAsSentTo(uid);
                    Console.WriteLine($"[INFO] Sent reciprocal public key to UID: {uid}");
                }
            }

            // Update the encryption status icon to reflect the current global key exchange state
            (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon();
        }

        /// <summary>
        /// Represents the user's preference for minimizing the app to the system tray.
        /// When changed, it updates the application setting, saves it, and shows or hides the tray icon accordingly.
        /// This property is bound to the ReduceToTray toggle in the settings UI.
        /// </summary>
        public bool ReduceToTray
        {
            get => chat_client.Properties.Settings.Default.ReduceToTray;
            set
            {
                if (chat_client.Properties.Settings.Default.ReduceToTray != value)
                {
                    chat_client.Properties.Settings.Default.ReduceToTray = value;
                    chat_client.Properties.Settings.Default.Save();

                    OnPropertyChanged(nameof(ReduceToTray));

                    // Updates tray icon visibility
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        var trayIcon = mainWindow.TryFindResource("TrayIcon") as TaskbarIcon;
                        if (trayIcon != null)
                        {
                            trayIcon.Visibility = value ? Visibility.Visible : Visibility.Collapsed;
                        }
                    }
                }
            }
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
        /// Resets the encryption state after the toggle is disabled.
        /// Clears the stored public key and updates the encryption setting in application settings.
        /// This ensures that encryption can be reinitialized cleanly if reactivated later.
        /// Does not dispose RSA keys directly; assumes stateless reinitialization on next activation.
        /// The method is stateless: it does not rely on internal flags, but on actual content and settings.
        /// </summary>
        public void ResetEncryptionState()
        {
            // Disable encryption in application settings
            Properties.Settings.Default.UseEncryption = false;
            Properties.Settings.Default.Save();

            // Clear stored public key from the user model
            if (LocalUser != null)
            {
                LocalUser.PublicKeyBase64 = null;
            }

            // Optional: log or notify if needed
        }

        /// <summary>
        /// Attempts to decrypt an incoming encrypted message using the local RSA private key.
        /// Validates encryption state and key readiness before proceeding.
        /// Cleans up the encrypted payload to remove invalid characters, then delegates decryption to EncryptionHelper.
        /// If decryption succeeds, returns the plain text message; otherwise, returns a localized fallback string.
        /// Designed to ensure graceful failure handling.
        /// </summary>
        public string TryDecryptMessage(string encryptedPayload)
        {
            // Validates encryption state and key readiness
            if (!IsEncryptionEnabled ||
                string.IsNullOrEmpty(encryptedPayload) ||
                !EncryptionHelper.IsPrivateKeyValid())
            {
                return LocalizationManager.GetString("DecryptionFailed");
            }

            try
            {
                string sanitizedPayload = encryptedPayload
                    .Replace("\0", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();

                string decrypted = EncryptionHelper.DecryptMessage(sanitizedPayload);
                return decrypted;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Decryption failed: {ex.Message}");
                return LocalizationManager.GetString("DecryptionFailed");
            }
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
