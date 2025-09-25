/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.MVVM.View;
using chat_client.Net;
using chat_client.Net.IO;
using chat_client.Properties;
using ChatClient.Helpers;
using Hardcodet.Wpf.TaskbarNotification;
using Microsoft.VisualBasic.ApplicationServices;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
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
    /// <summary>
    /// Central view model for the client application.
    /// Manages user identity, message flow, encryption state, and UI bindings.
    /// Subscribes to server-side events to handle incoming connections, messages, and disconnections.
    /// Maintains observable collections for connected users and chat messages.
    /// Coordinates handshake alignment, encryption readiness, and UI state transitions.
    /// </summary>
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
            "😀", "👍", "🙏", "😅", "😂", "🤣", "😉", "😎", "😤", "😏", "🙈", "👋", "💪",
            "👌", "📌", "📞", "🔍", "⚠️", "✓", "🤝", "📣", "🚀", "☕", "🍺", "🍻", "🎉", 
            "🍾", "🥳", "🍰", "🍱", "😁", "😇", "🤨", "🤷", "🤐", "😘", "❤️", "😲", "😬", 
            "😷", "😴", "💤", "🔧", "🚗", "🏡", "☀️",  "🔥", "⭐", "🌟", "✨", "🌧️", "🕒"
        };

        /// <summary>
        /// Observable property that indicates whether encryption is fully ready for use.
        /// Implements INotifyPropertyChanged to allow the UI to react automatically when the value changes.
        /// This enables MVVM-compliant updates, such as triggering icon refreshes or animations in the view.
        /// This becomes true only when encryption is enabled and all required public keys are received.
        /// </summary>
        public bool IsEncryptionReady
        {
            get => _isEncryptionReady;
            set
            {
                if (_isEncryptionReady != value)
                {
                    _isEncryptionReady = value;
                    OnPropertyChanged(nameof(IsEncryptionReady));
                }
            }
        }

        /// <summary>
        /// Static UID used to identify system-originated messages such as server shutdown or administrative commands.
        /// This allows clients to verify message authenticity and prevent spoofed disconnects or control signals.
        /// </summary>
        public static readonly Guid SystemUID = Guid.Parse("00000000-0000-0000-0000-000000000001");

        /// <summary>
        /// Indicates whether the client is currently connected to the server.
        /// This property is bound to UI elements (e.g., visibility toggles, button labels).
        /// When its value changes, it triggers a notification via OnPropertyChanged(),
        /// allowing the UI to automatically update without manual refresh.
        /// Encapsulating the backing field (_isConnected) ensures controlled updates,
        /// prevents silent overwrites, and enables change detection logic.
        /// This pattern is essential in MVVM to maintain reactive, state-driven interfaces.
        /// </summary>
        public bool IsConnected
        {
            get => _isConnected;
            set
            {
                // Only update if the value has actually changed
                if (_isConnected != value)
                {
                    _isConnected = value;

                    // Notifies the UI that the property has changed
                    // This triggers any bindings to refresh automatically
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Stores public keys of other connected users, indexed by their UID.
        /// Used for encrypting messages to specific recipients.
        /// </summary>
        public Dictionary<string, string> KnownPublicKeys { get; } = new();

        /// <summary>
        /// Initializes the main view model and subscribes to server-side events.
        /// Handles user connection, message reception, and disconnection via event-driven architecture.
        /// </summary>

 
        /// <summary>
        /// Represents the number of clients expected to be connected for encryption readiness.
        /// This value is updated dynamically based on the current user list.
        /// </summary>
        public int ExpectedClientCount { get; set; } = 1; // Starts at 1 (self)

        /// <summary>
        /// Event triggered when a property value changes, used to notify bound UI elements in data-binding scenarios.
        /// Implements the INotifyPropertyChanged interface to support reactive updates in WPF.
        /// </summary>
        public event PropertyChangedEventHandler PropertyChanged;

        /// <summary>
        /// Notifies UI bindings that a property value has changed, enabling automatic interface updates.
        /// </summary>
        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <summary>
        /// Tracks whether the client has successfully established a connection to the server.
        /// </summary>
        private bool _isConnected;

        /// <summary>
        /// Indicates whether the client has received all required public keys for secure encrypted communication.
        /// </summary>
        private bool _isEncryptionReady;


        /// <summary>
        /// Tracks which users have already received our public RSA key.
        /// A HashSet has these advantages :
        /// - No duplicates: a UID can only be added once. This prevent redundant key transmissions.
        /// - Fast: the Contains and Add operations are in constant time
        /// - Readable: the logic is clear and explicit
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

            // Subscribes to server events
            _server.connectedEvent += UserConnected;
            _server.msgReceivedEvent += MessageReceived;
            _server.userDisconnectEvent += UserDisconnected;
        }


        /// <summary>
        /// Checks whether encryption is fully ready for secure communication.
        /// Returns true only if encryption is enabled, the local public key is present,
        /// and every other connected user has a known public key.
        /// Logs missing UIDs for debugging. This method guarantees strict readiness before encrypted messages are allowed.
        /// </summary>
        /// <returns>True if all required public keys are present; otherwise, false.</returns>
        public bool AreAllKeysReceived()
        {
            // Encryption must be enabled in settings
            if (!chat_client.Properties.Settings.Default.UseEncryption)
                return false;

            // Local public key must be defined
            if (string.IsNullOrEmpty(LocalUser?.PublicKeyBase64))
                return false;

            // User list must be available and contain at least one peer
            if (Users == null || Users.Count <= 1)
                return false;

            // Prepares a list to track UIDs of users whose public key is missing
            List<string> missingPeerUids = new();

            // Iterates through all connected users to verify that each has a known public key
            foreach (var connectedUser in Users)
            {
                // Skips the local client
                if (connectedUser.UID == LocalUser.UID)
                    continue;

                // Adds UID to the missing list if no public key is registered
                if (!KnownPublicKeys.TryGetValue(connectedUser.UID, out string peerKey) || string.IsNullOrEmpty(peerKey))
                    missingPeerUids.Add(connectedUser.UID);
            }

            // Logs missing UIDs if any
            if (missingPeerUids.Count > 0)
            {
                string joined = string.Join(", ", missingPeerUids);
                ClientLogger.Log($"Encryption not ready — missing keys for: {joined}", LogLevel.Debug);
                return false;
            }

            // All keys are present and valid
            return true;
        }


        /// <summary>
        /// Determines whether a message can be encrypted for the specified recipient.
        /// Requires that encryption is enabled, the local key is initialized,
        /// and the recipient's public key is available.
        /// </summary>
        /// <param name="recipientUID">Unique identifier of the recipient user.</param>
        /// <returns>True if encryption is possible; otherwise, false.</returns>
        public bool CanEncryptMessageFor(string recipientUID)
        {
            // Encryption must be enabled in settings
            if (!chat_client.Properties.Settings.Default.UseEncryption)
                return false;

            // Local key must be initialized
            if (string.IsNullOrEmpty(LocalUser?.PublicKeyBase64))
                return false;

            // Recipient's public key must be known
            if (!KnownPublicKeys.ContainsKey(recipientUID))
                return false;

            return true;
        }

        /// <summary>
        /// Starts the client connection process:
        /// validates the username, performs the TCP handshake to obtain UID and initial public key,
        /// populates LocalUser, marks the connection as established,
        /// then reuses a stored RSA key pair if present, or initializes encryption otherwise,
        /// re-publishes the public key on reconnect, triggers key synchronization,
        /// updates the UI to connected state, and saves the last used IP.
        /// </summary>
        public void Connect()
        {
            // Reject empty usernames
            if (string.IsNullOrWhiteSpace(Username))
            {
                ShowUsernameError();
                return;
            }
            
            // Enforces allowed characters: A-Z, a-z, digits, and selected accented letters only
            var allowedPattern = @"^[a-zA-Z0-9éèàöüî_-]+$";

            // Rejects malformed usernames that contain any other character
            if (!Regex.IsMatch(Username, allowedPattern))
            {
                ShowUsernameError();
                return;
            }


            try
            {
                // Performs TCP handshake and retrieve UID + server public key
                var result = _server.ConnectToServer(Username.Trim(), IPAddressOfServer);
                if (result.uid == Guid.Empty || string.IsNullOrEmpty(result.publicKeyBase64))
                    throw new Exception(LocalizationManager.GetString("ConnectionFailed"));

                // Initializes LocalUser with server-provided identity
                LocalUser = new UserModel
                {
                    Username = Username.Trim(),
                    UID = result.uid.ToString(),
                    PublicKeyBase64 = result.publicKeyBase64
                };
                ClientLogger.Log($"LocalUser initialized — Username: {LocalUser.Username}, UID: {LocalUser.UID}", LogLevel.Debug);

                // Marks connection as successful (plain chat allowed)
                IsConnected = true;
                ClientLogger.Log("Client connected — plain messages allowed before handshake.", LogLevel.Debug);

                if (Properties.Settings.Default.UseEncryption)
                {
                    // Loads stored RSA key pair if available
                    var storedPub = Properties.Settings.Default.HandshakePublicKey;
                    var storedPriv = Properties.Settings.Default.HandshakePrivateKey;
                    if (!string.IsNullOrEmpty(storedPub) && !string.IsNullOrEmpty(storedPriv))
                    {
                        LocalUser.PublicKeyBase64 = storedPub;
                        LocalUser.PrivateKeyBase64 = storedPriv;
                        EncryptionHelper.SetPrivateKey(storedPriv);
                        ClientLogger.Log("Loaded existing RSA key pair from settings.", LogLevel.Debug);

                        // Re-publishes public key to server after reconnect
                        Server.SendPublicKeyToServer(LocalUser.UID, storedPub);
                        _server.RequestAllPublicKeysFromServer();
                    }

                    // Initializes encryption if no stored pair found
                    InitializeEncryption(this);
                    ClientLogger.Log("Encryption initialized on startup.", LogLevel.Info);

                    // Triggers key synchronization
                    _server.ResendPublicKey();
                    _server.RequestAllPublicKeysFromServer();
                }

                // Updates UI to connected state
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        mainWindow.Title += " - " + LocalizationManager.GetString("Connected");
                        mainWindow.cmdConnectDisconnect.Content = "_Disconnect";
                        mainWindow.spnDown.Visibility = Visibility.Visible;
                        mainWindow.spnEmojiPanel.Visibility = Visibility.Visible;
                        mainWindow.txtMessageToSend.Focus();
                    }
                });

                // Save the last used IP address for future sessions
                Properties.Settings.Default.LastIPAddressUsed = IPAddressOfServer;
                Properties.Settings.Default.Save();
            }
            catch (Exception)
            {
                // Handles connection failure and reset UI
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mw)
                    {
                        MessageBox.Show(
                            LocalizationManager.GetString("ServerUnreachable"),
                            LocalizationManager.GetString("Error"),
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                        ReinitializeUI();
                    }
                });
            }
        }


        /// <summary>
        /// Connects or disconnects the client, depending on the connection status
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
                // Attempts to close the connection to the server
                _server.DisconnectFromServer();

                // Resets the UI and clear user/message data
                ReinitializeUI();
            }
            catch (Exception ex)
            {
                // Displays an error message if disconnection fails
                MessageBox.Show(LocalizationManager.GetString("ErrorWhileDisconnecting") + ex.Message, LocalizationManager.GetString("Error"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Evaluates the current encryption state by checking whether all required public keys are received.
        /// Updates the IsEncryptionReady property, which triggers UI updates via data binding.
        /// Should be called whenever the Users list changes or a new public key is received.
        /// </summary>
        public void EvaluateEncryptionState()
        {
            IsEncryptionReady = AreAllKeysReceived();
            ClientLogger.Log($"EvaluateEncryptionState called — Ready: {IsEncryptionReady}", LogLevel.Debug);
        }

        /// <summary>
        /// Returns all known public RSA keys from the current Users list.
        /// Filters out users without keys and includes the local user.
        /// </summary>
        public Dictionary<string, string> GetAllKnownPublicKeys()
        {
            var keys = new Dictionary<string, string>();

            foreach (var user in Users)
            {
                if (!string.IsNullOrEmpty(user.UID) && !string.IsNullOrEmpty(user.PublicKeyBase64))
                {
                    keys[user.UID] = user.PublicKeyBase64;
                }
            }

            return keys;
        }

        /// <summary>
        /// Returns the current port number stored in application settings.
        /// </summary>
        public static int GetCurrentPort()
        {
            return chat_client.Properties.Settings.Default.CustomPortNumber;
        }

        /// <summary>
        /// Handles a system-issued disconnect command.
        /// Clears the user list, posts a system message, and updates connection status.
        /// </summary>
        private void HandleSystemDisconnect()
        {
            // Executes UI-bound actions on the main thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                Users.Clear();
                Messages.Add("# - " + LocalizationManager.GetString("SystemDisconnected") + " #");
                IsConnected = false;
            });
        }

        /// <summary>
        /// Initializes RSA encryption for the current session.
        /// This method is safe to call multiple times and ensures the client can
        /// send and receive encrypted messages. It generates a new RSA key pair,
        /// stores it in the LocalUser object, injects the private key, sends the public key
        /// to the server, registers known keys locally, requests missing keys if needed,
        /// evaluates readiness, and triggers a final sync. All settings are saved once at the end.
        /// </summary>
        public bool InitializeEncryption(MainViewModel viewModel)
        {
            // Skips if LocalUser is not set or encryption is already active
            if (LocalUser == null || EncryptionHelper.IsEncryptionActive)
            {
                ClientLogger.Log("Encryption initialization skipped — LocalUser is null or already active.", LogLevel.Debug);
                return false;
            }

            bool initializationSucceeded = false;

            try
            {
                // Generates RSA key pair (2048-bit)
                using var rsa = new RSACryptoServiceProvider(2048);
                string publicKeyXml = rsa.ToXmlString(false);
                string privateKeyXml = rsa.ToXmlString(true);

                // Encodes keys in Base64
                string publicKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyXml));
                string privateKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyXml));

                // Stores keys in LocalUser model
                LocalUser.PublicKeyBase64 = publicKeyBase64;
                LocalUser.PrivateKeyBase64 = privateKeyBase64;
                ClientLogger.Log($"RSA key pair generated — UID: {LocalUser.UID}", LogLevel.Debug);

                // Injects private key into decryption helper
                EncryptionHelper.SetPrivateKey(privateKeyBase64);
                ClientLogger.Log("Private key injected into EncryptionHelper.", LogLevel.Debug);

                // Registers the client’s own public key locally
                if (!string.IsNullOrEmpty(LocalUser.UID))
                {
                    KnownPublicKeys[LocalUser.UID] = publicKeyBase64;
                    ClientLogger.Log($"Local public key registered — UID: {LocalUser.UID}", LogLevel.Debug);
                }

                // Sends the public key to the server for distribution
                bool sent = Server.SendPublicKeyToServer(LocalUser.UID, publicKeyBase64);
                if (!sent)
                {
                    MessageBox.Show(
                        LocalizationManager.GetString("SendingClientsPublicRSAKeyToTheServerFailed"),
                        LocalizationManager.GetString("Error"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);

                    // Mark encryption disabled on failure
                    Properties.Settings.Default.UseEncryption = false;
                    ClientLogger.Log("Failed to send public key to server — encryption disabled.", LogLevel.Error);
                    return false;
                }

                // Marks encryption enabled in settings
                Properties.Settings.Default.UseEncryption = true;
                initializationSucceeded = true;
                ClientLogger.Log("Encryption enabled in settings.", LogLevel.Debug);

                // Registers any known public keys from the local user list
                foreach (var (peerUid, peerKey) in viewModel.GetAllKnownPublicKeys())
                {
                    if (!KnownPublicKeys.ContainsKey(peerUid))
                    {
                        KnownPublicKeys[peerUid] = peerKey;
                        ClientLogger.Log($"External public key registered — UID: {peerUid}", LogLevel.Debug);
                    }
                }

                // Requests full key synchronization if the set is incomplete
                if (KnownPublicKeys.Count < ExpectedClientCount)
                {
                    _server.RequestAllPublicKeysFromServer();
                    ClientLogger.Log("Full public-key sync requested due to incomplete keyset.", LogLevel.Debug);
                }

                // Evaluates readiness and update UI
                EvaluateEncryptionState();
                if (IsEncryptionReady)
                {
                    (Application.Current.MainWindow as MainWindow)
                        ?.UpdateEncryptionStatusIcon(IsEncryptionReady);
                    ClientLogger.Log($"Encryption readiness confirmed — All {ExpectedClientCount} public keys received.", LogLevel.Debug);
                }
                else
                {
                    ClientLogger.Log($"[DEBUG] Encryption incomplete — {KnownPublicKeys.Count}/{ExpectedClientCount} public keys received.", LogLevel.Debug);
                }

                // Final sync pass to recover any missing keys
                SyncKeys();

                return true;
            }
            catch (Exception ex)
            {
                // Disables encryption on exception
                Properties.Settings.Default.UseEncryption = false;
                ClientLogger.Log($"Exception during encryption initialization: {ex.Message}", LogLevel.Error);
                return false;
            }
            finally
            {
                //Saves handshake key pair and encryption setting once
                Properties.Settings.Default.HandshakePublicKey = LocalUser?.PublicKeyBase64;   // saves public key
                Properties.Settings.Default.HandshakePrivateKey = LocalUser?.PrivateKeyBase64;  // saves private key
                Properties.Settings.Default.Save();                                             // save all settings in one call
                ClientLogger.Log("Settings saved.", LogLevel.Debug);
            }
        }

        /// <summary>
        /// Handles incoming chat packets (opcode 5) by reading three fields in sequence:
        /// senderUid, recipientUid, then raw content.  
        /// Filters out unicast packets not addressed to this client.  
        /// Processes system-issued “/disconnect” commands.  
        /// Decrypts payloads prefixed “[ENC]” with fallback on failure.  
        /// Resolves the sender’s display name and dispatches the formatted message to the UI dispatcher.
        /// </summary>
        private void MessageReceived()
        {
            // Reads the UID of the sender
            string senderUid = _server.PacketReader.ReadMessage();

            // Reads the UID of the intended recipient (empty string = broadcast)
            string recipientUid = _server.PacketReader.ReadMessage();

            // Reads the message content, which may be plain text or "[ENC]" + ciphertext
            string rawContent = _server.PacketReader.ReadMessage();

            // Ignores unicast messages not meant for this client
            if (!string.IsNullOrEmpty(recipientUid)
                && recipientUid != LocalUser.UID)
            {
                return;
            }

            // Processes system disconnect requests
            if (rawContent == "/disconnect"
                && senderUid == SystemUID.ToString())
            {
                HandleSystemDisconnect();
                return;
            }

            // Resolves the display name: find in Users, otherwise fallbacks to local user or UID
            string displayName = Users
                .FirstOrDefault(u => u.UID.ToString() == senderUid)?.Username
                ?? (LocalUser?.UID.ToString() == senderUid ? LocalUser.Username : senderUid);

            string finalMessage;

            // Decrypts encrypted payloads
            if (rawContent.StartsWith("[ENC]"))
            {
                // Strips the "[ENC]" marker and cleans up any stray control characters
                string encryptedPayload = rawContent
                    .Substring(5)
                    .Replace("\0", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();

                try
                {
                    // Attempts decryption using the local private key
                    string decrypted = TryDecryptMessage(encryptedPayload);
                    finalMessage = $"{displayName}: {decrypted}";
                }
                catch (Exception ex)
                {
                    // Fallbacks on decryption failure
                    finalMessage = $"{displayName}: {LocalizationManager.GetString("DecryptionFailed")} ({ex.Message})";
                }
            }
            else
            {
                // Plain-text fallback
                finalMessage = $"{displayName}: {rawContent}";
            }

            // Dispatches the formatted message to the UI thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                Messages.Add(finalMessage);
            });
        }

        /// <summary>
        /// Receives and registers a public RSA key from another client in the network.
        /// This method is central to the multi-client encryption protocol: it ensures that each client
        /// maintains an up-to-date dictionary of peer public keys required for secure message decryption.
        /// Upon receiving a key, it re-evaluates encryption readiness and updates the UI lock icon
        /// only when the full key set is present. This guarantees that visual feedback reflects
        /// actual decryption capability, avoiding premature or misleading UI states.
        /// Designed to be idempotent and resilient to duplicate key transmissions.
        /// </summary>
        /// <param name="uid">The UID of the user whose public key is received.</param>
        /// <param name="publicKeyBase64">The Base64-encoded public key.</param>
        public void ReceivePublicKey(string uid, string publicKeyBase64)
        {
            if (string.IsNullOrWhiteSpace(uid) || string.IsNullOrWhiteSpace(publicKeyBase64))
                return;

            // Stores or updates the received public key in the local dictionary
            KnownPublicKeys[uid] = publicKeyBase64;

            // Re-evaluates encryption readiness based on the current number of known keys
            EvaluateEncryptionState();

            // Logs key reception and current readiness status for diagnostics
            int publicKeyCount = KnownPublicKeys?.Count ?? 0;
            ClientLogger.Log($"Public key received for UID: {uid} — Total keys: {publicKeyCount}, Ready: {IsEncryptionReady}", LogLevel.Debug);

            // Updates the lock icon only when all expected keys have been received
            // This ensures that the visual indicator reflects true decryption capability
            if (publicKeyCount == ExpectedClientCount)
            {
                (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady);
                ClientLogger.Log($"Encryption readiness confirmed — All {ExpectedClientCount} public keys received.", LogLevel.Debug);
            }
            else
            {
                ClientLogger.Log($"Encryption incomplete — {publicKeyCount}/{ExpectedClientCount} public keys received.", LogLevel.Debug);
            }
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
                    mainWindow.Title = "WPF chat client";

                    // Hides the down and toolbar panels
                    mainWindow.spnDown.Visibility = Visibility.Hidden;
                    mainWindow.spnEmojiPanel.Visibility = Visibility.Hidden;
                }
            });
        }

        /// <summary>
        /// Applies a red border style to the username textbox to visually indicate invalid input.
        /// </summary>
        private void ShowUsernameError()
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow)
                {
                    mainWindow.txtUsername.Style = mainWindow.TryFindResource("ErrorTextBoxStyle") as Style;
                    mainWindow.txtUsername.Focus();
                }
            });
        }

        /// <summary>
        /// Verifies that all connected users have a known public RSA key.
        /// If missing keys are detected, attempts recovery by resending the local public key.
        /// Triggers a UI update to reflect synchronization status and tooltip state.
        /// Should be called after list of users updates or key exchange events.
        /// </summary>
        public void SyncKeys()
        {
            // Skips synchronization if encryption is disabled or list of users is unavailable
            if (!chat_client.Properties.Settings.Default.UseEncryption || Users == null || Users.Count == 0)
                return;

            List<string> missing = new();

            // Iterates through all connected users (excluding self) to verify public key availability.
            // For each user, checks whether their UID is present in the KnownPublicKeys dictionary.
            // If a key is missing, the UID is added to the 'missing' list to trigger recovery logic.
            // Designed to support dynamic multi-client environments where users may join or reconnect at any time.

            foreach (var user in Users)
            {
                if (user.UID == LocalUser.UID)
                    continue;

                if (!KnownPublicKeys.ContainsKey(user.UID))
                    missing.Add(user.UID);
            }

            // Logs missing keys for debugging
            if (missing.Count > 0)
            {
                ClientLogger.Log($"Missing keys detected: {string.Join(", ", missing)}", LogLevel.Debug);

                // Attempts to resend the local public key to the server
                _server.ResendPublicKey();
            }

            // Updates encryption readiness and UI icon with sync state
            bool isSyncing = missing.Count > 0;
            (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady, isSyncing);
        }

        /// <summary>
        /// Attempts to decrypt the incoming Base64 ciphertext using EncryptionHelper.
        /// Validates encryption settings, payload integrity, and private key readiness.
        /// Logs each step for diagnostics and returns plaintext or a localized error string.
        /// </summary>
        /// <param name="encryptedPayload">The Base64-encoded encrypted payload.</param>
        /// <returns>The decrypted plaintext if successful; otherwise, a fallback message.</returns>
        public static string TryDecryptMessage(string encryptedPayload)
        {
            ClientLogger.Log("TryDecryptMessage called.", LogLevel.Debug);

            if (!Settings.Default.UseEncryption)
            {
                ClientLogger.Log("Encryption is disabled in application settings.", LogLevel.Warn);
                return LocalizationManager.GetString("DecryptionFailed");
            }

            if (string.IsNullOrWhiteSpace(encryptedPayload))
            {
                ClientLogger.Log("Encrypted payload is null or empty.", LogLevel.Warn);
                return LocalizationManager.GetString("DecryptionFailed");
            }

            try
            {
                ClientLogger.Log($"Raw encrypted payload: {encryptedPayload}", LogLevel.Debug);

                // Sanitizes payload: strips control chars and trims whitespace.
                string sanitized = encryptedPayload
                    .Replace("\0", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();
                ClientLogger.Log($"Sanitized encrypted payload: {sanitized}", LogLevel.Debug);

                // Delegates to EncryptionHelper for the actual decrypt.
                string result = EncryptionHelper.DecryptMessage(sanitized);
                ClientLogger.Log($"Decryption successful. Decrypted message: {result}", LogLevel.Debug);

                return result;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Exception during decryption: {ex.Message}", LogLevel.Error);
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

        /// <summary>
        /// Evaluates the current encryption readiness state and updates the lock icon accordingly.
        /// Should be called whenever the list of users changes or new public keys are received.
        /// Provides visual feedback to the user and logs key distribution status for traceability.
        /// Designed to support dynamic multi-client encryption in a public chat context.
        /// </summary>
        public void UpdateEncryptionStatus()
        {
            // Re-evaluates encryption readiness based on list of users and known public keys
            EvaluateEncryptionState();

            // Logs each user in the list of users and whether their public key is known
            if (Users != null)
            {
                foreach (var user in Users)
                {
                    bool hasKey = KnownPublicKeys.ContainsKey(user.UID);
                    ClientLogger.Log($"User in list of users — UID: {user.UID}, HasKey: {hasKey}", LogLevel.Debug);
                }
            }

            // Logs the readiness state before updating the icon
            ClientLogger.Log($"UpdateEncryptionStatusIcon called — isReady: {IsEncryptionReady}", LogLevel.Debug);

            // Delegates icon update to the UI layer
            (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady);

            // Logs summary of list of users and key distribution
            int userCount = Users?.Count ?? 0;
            int keyCount = KnownPublicKeys?.Count ?? 0;
            ClientLogger.Log($"Encryption status updated — Users: {userCount}, Keys: {keyCount}, Ready: {IsEncryptionReady}", LogLevel.Debug);
        }

        /// <summary>
        /// Handles the arrival of a new user by reading their identity and public key from the incoming packet.
        /// Expects fields in the order: UID → Username → PublicKey.
        /// Adds the user to the observable Users collection if not already present.
        /// Registers their RSA key and re-evaluates encryption readiness.
        /// UI-bound actions are dispatched to the main thread to ensure thread safety.
        /// This method is triggered by opcode 1 and corresponds to the server-side BroadcastUserList().
        /// </summary>
        public void UserConnected()
        {
            // Reads identity fields from the incoming packet in expected order
            var uid = _server.PacketReader.ReadMessage();         // First: UID
            var username = _server.PacketReader.ReadMessage();    // Second: Username
            var publicKey = _server.PacketReader.ReadMessage();   // Third: RSA public key

            // Prevents duplicate entries by checking if the UID already exists
            if (!Users.Any(x => x.UID == uid))
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    // Creates a new user model with received identity
                    var user = new UserModel
                    {
                        UID = uid,
                        Username = username,
                        PublicKeyBase64 = publicKey
                    };

                    // Adds the user to the observable collection bound to the UI
                    Users.Add(user);

                    // Updates the expected client count for encryption readiness evaluation
                    ExpectedClientCount = Users.Count;
                    ClientLogger.Log($"ExpectedClientCount updated — Total users: {ExpectedClientCount}", LogLevel.Debug);

                    // Registers the public key if not already known
                    if (!KnownPublicKeys.ContainsKey(user.UID))
                    {
                        KnownPublicKeys[user.UID] = publicKey;
                        ClientLogger.Log($"Public key registered for {username} — UID: {uid}", LogLevel.Debug);
                    }

                    // Re-evaluates encryption readiness after adding the new user
                    EvaluateEncryptionState();

                    // Posts a system message unless triggered during initial roster load
                    if (Message != null)
                    {
                        Messages.Add("# - " + user.Username + " " + LocalizationManager.GetString("HasConnected") + ". #");
                    }
                });
            }
        }

        /// <summary>
        /// Handles the disconnection of a remote user.
        /// Removes the user from the Users collection and posts a system message.
        /// Re-evaluates encryption readiness if encryption is enabled.
        /// </summary>
        public void UserDisconnected()
        {
            // Reads the UID of the disconnected user from the incoming packet
            var uid = _server.PacketReader.ReadMessage();

            // Locates the user in the current Users collection
            var user = Users.FirstOrDefault(x => x.UID == uid);

            if (user != null)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    // Removes the user from the active list
                    Users.Remove(user);

                    // Updates the expected client count after user removal
                    ExpectedClientCount = Users.Count;
                    ClientLogger.Log($"ExpectedClientCount updated — Total users: {ExpectedClientCount}", LogLevel.Debug);

                    // Posts a localized system message to the chat
                    Messages.Add("# - " + user.Username + " " + LocalizationManager.GetString("HasDisconnected") + ". #");

                    // Re-evaluates encryption state only if encryption is enabled
                    if (chat_client.Properties.Settings.Default.UseEncryption)
                    {
                        UpdateEncryptionStatus();
                    }

                    ClientLogger.Log($"User disconnected — Username: {user.Username}, UID: {uid}", LogLevel.Debug);
                });
            }
        }
    }
}
