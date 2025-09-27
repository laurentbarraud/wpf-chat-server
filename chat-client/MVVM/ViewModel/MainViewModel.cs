/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 28th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.Net;
using chat_client.Properties;
using Hardcodet.Wpf.TaskbarNotification;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;

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
        // PUBLIC PROPERTIES

        /// <summary>
        /// Represents a dynamic data collection that provides notification
        /// when items are added or removed, or when the full list is refreshed.
        /// </summary>
        public ObservableCollection<UserModel> Users { get; set; }

        public ObservableCollection<string> Messages { get; set; }

        // What the user types in the first textbox on top left of
        // the MainWindow in View gets stored in this property (bound in XAML).
        public static string Username { get; set; } = string.Empty;

        // What the user types in the second textbox on top left of
        // the MainWindow in View gets stored in this property (bound in XAML).
        public static string IPAddressOfServer { get; set; } = string.Empty;

        // What the user types in the textbox on bottom right
        // of the MainWindow in View gets stored in this property (bound in XAML).
        public static string Message { get; set; } = string.Empty;

        /// <summary>
        /// Static UID used to identify system-originated messages such as server shutdown or administrative commands.
        /// This allows clients to verify message authenticity and prevent spoofed disconnects or control signals.
        /// </summary>
        public static readonly Guid SystemUID = Guid.Parse("00000000-0000-0000-0000-000000000001");

        /// <summary>
        /// Indicates whether the client is currently connected to the server.
        /// Delegates to the Server’s IsConnected property.
        /// </summary>
        public bool IsConnected => _server.IsConnected;

        private static readonly Dictionary<string, string> dictionary = new();

        /// <summary>
        /// Stores public keys of other connected users, indexed by their UID.
        /// Used for encrypting messages to specific recipients.
        /// </summary>
        public Dictionary<string, string> KnownPublicKeys { get; } = dictionary;

        /// <summary>
        /// Represents the number of clients expected to be connected for encryption readiness.
        /// This value is updated dynamically based on the current user list.
        /// </summary>
        public int ExpectedClientCount { get; set; } = 1; // Starts at 1 (self)

        /// <summary>
        /// Indicates whether encryption is fully ready for use.
        /// True when encryption is enabled and all required public keys are received.
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
        /// Gets whether encryption is currently synchronizing peer public keys.
        /// Returns true when encryption is enabled but not all keys have been received.
        /// </summary>
        public bool IsEncryptionSyncing
        {
            get => Settings.Default.UseEncryption && !AreAllKeysReceived();
        }

        /// <summary>
        /// Indicates whether a key‐exchange handshake is currently in progress.
        /// While true, the encryption toggle remains disabled to prevent state changes
        /// during the handshake and ensure a consistent cryptographic setup.
        /// </summary>
        public bool IsKeyExchangeInProgress
        {
            get => _isKeyExchangeInProgress;
            private set
            {
                if (_isKeyExchangeInProgress != value)
                {
                    _isKeyExchangeInProgress = value;
                    OnPropertyChanged(nameof(IsKeyExchangeInProgress));
                }
            }
        }

        /// <summary>
        /// Checks whether the local user has already sent their public key to the specified UID.
        /// </summary>
        /// <param name="uid">Unique identifier of the remote user.</param>
        /// <returns>True if the key has already been sent; otherwise, false.</returns>
        public bool HasSentKeyTo(string uid) => _uidsKeySentTo.Contains(uid);

        /// <summary>
        /// Marks the specified UID as having received our public RSA key.
        /// Prevents duplicate transmissions during key exchange.
        /// </summary>
        /// <param name="uid">Unique identifier of the remote user.</param>
        public void MarkKeyAsSentTo(string uid) => _uidsKeySentTo.Add(uid);

        // Declaring the list as public ensures it can be resolved by WPF's binding system,
        // assuming the containing object is set as the DataContext.
        public List<string> EmojiList { get; } = new()
        {
            "😀", "👍", "🙏", "😅", "😂", "🤣", "😉", "😎", "😤", "😏", "🙈", "👋", "💪",
            "👌", "📌", "📞", "🔍", "⚠️", "✓", "🤝", "📣", "🚀", "☕", "🍺", "🍻", "🎉",
            "🍾", "🥳", "🍰", "🍱", "😁", "😇", "🤨", "🤷", "🤐", "😘", "❤️", "😲", "😬",
            "😷", "😴", "💤", "🔧", "🚗", "🏡", "☀️",  "🔥", "⭐", "🌟", "✨", "🌧️", "🕒"
        };

        public UserModel? LocalUser { get; set; }

        public Server _server = new Server();

        /// <summary>
        /// Event triggered when a property value changes, used to notify bound UI elements in data-binding scenarios.
        /// Implements the INotifyPropertyChanged interface to support reactive updates in WPF.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;

        // PROTECTED METHODS

        /// <summary>
        /// Notifies UI bindings that a property value has changed, enabling automatic interface updates.
        /// </summary>
        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        // PRIVATE FIELDS

        // Backing field for change notification
        private bool _isEncryptionReady;

        // Flag for ongoing key exchange
        private bool _isKeyExchangeInProgress;

        /// <summary>
        /// Tracks which users have already received our public RSA key.
        /// A HashSet has these advantages :
        /// - No duplicates: a UID can only be added once. This prevents redundant key transmissions.
        /// - Fast: the Contains and Add operations are in constant time.
        /// - Readable: the logic is clear and explicit.
        /// </summary>
        private readonly HashSet<string> _uidsKeySentTo = new();

        /// <summary>
        /// Initializes the ViewModel, sets up collections,
        /// instantiates the Server client, and wires its events to Raise helpers.
        /// </summary>
        public MainViewModel()
        {
            // Initializes the collections bound to the UI
            Users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<string>();

            // Creates the server‐side client and hooks its events
            _server = new Server();

            // Model A: new user joined → (uid, username, publicKey)
            _server.ConnectedEvent += UserConnected;

            // Model C: plain-text message arrives → (formattedMessage)
            _server.PlainMessageReceivedEvent += PlainMessageReceived;

            // Model E: encrypted message arrives → (formattedMessage)
            _server.EncryptedMessageReceivedEvent += EncryptedMessageReceived;

            // Model D: peer public key arrives → (senderUid, publicKeyBase64)
            _server.PublicKeyReceivedEvent += PublicKeyReceived;

            // Model A: a user disconnected → (uid, username)
            _server.UserDisconnectedEvent += UserDisconnected;

            // Model F: server-initiated disconnect → no arguments
            _server.DisconnectedByServerEvent += ServerDisconnectedClient;
        }
 
        /// <summary>
        /// Determines whether encryption can proceed by checking:
        ///  - if encryption is enabled in settings  
        ///  - if Local user and its public key are initialized  
        ///  - if all connected peers have published a valid public key  
        /// Uses a lock on the shared key dictionary to ensure thread safety
        /// and logs each decision point for detailed troubleshooting.
        /// </summary>
        /// <returns>True if encryption is fully ready (including solo mode); otherwise, false.</returns>
        public bool AreAllKeysReceived()
        {
            // Logs the current encryption setting for debugging
            ClientLogger.ClientLog($"Checking encryption readiness — UseEncryption={Settings.Default.UseEncryption}",
                ClientLogLevel.Debug);

            // Skips if encryption is disabled or if the local user is not initialized
            if (!Settings.Default.UseEncryption || LocalUser == null)
            {
                ClientLogger.ClientLog("Skipping encryption readiness check — encryption disabled or local user not initialized.",
                    ClientLogLevel.Info);
                return false;
            }

            // Checks presence of the local public key
            bool hasLocalKey = !string.IsNullOrEmpty(LocalUser.PublicKeyBase64);
            ClientLogger.ClientLog(
                $"Local public key present: {hasLocalKey}",
                ClientLogLevel.Debug);

            if (!hasLocalKey)
            {
                ClientLogger.ClientLog(
                    "Skipping encryption readiness check — local public key not yet generated.",
                    ClientLogLevel.Info);
                return false;
            }

            // Handles solo mode where no peers are connected
            if (Users.Count == 0)
            {
                ClientLogger.ClientLog("Solo mode detected — no peers; encryption considered ready.",
                    ClientLogLevel.Debug);

                ClientLogger.ClientLog("Encryption is fully activated and ready (solo mode).",
                    ClientLogLevel.Info);
                return true;
            }

            List<string> missingKeys;

            // Locks the shared dictionary while computing missing entries
            lock (KnownPublicKeys)
            {
                var peerUids = Users.Select(u => u.UID).ToList();
                ClientLogger.ClientLog($"Peer UIDs to verify: {string.Join(", ", peerUids)}",
                    ClientLogLevel.Debug);

                missingKeys = peerUids
                    .Except(KnownPublicKeys.Keys)
                    .ToList();

                ClientLogger.ClientLog($"Number of missing keys detected: {missingKeys.Count}",
                    ClientLogLevel.Debug);
            }

            // Logs and aborts if any peer keys are missing
            if (missingKeys.Count > 0)
            {
                ClientLogger.ClientLog(
                    $"Encryption not ready — missing keys for: {string.Join(", ", missingKeys)}",
                    ClientLogLevel.Debug);
                return false;
            }

            // All checks passed: logs activation and returns readiness
            ClientLogger.ClientLog(
                "Encryption is fully activated and ready.",
                ClientLogLevel.Info);
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
                ClientLogger.ClientLog($"LocalUser initialized — Username: {LocalUser.Username}, UID: {LocalUser.UID}", ClientLogLevel.Debug);

                // Marks connection as successful (plain chat allowed)
                OnPropertyChanged(nameof(IsConnected));
                ClientLogger.ClientLog("Client connected — plain messages allowed before handshake.", ClientLogLevel.Debug);
                
                if (Properties.Settings.Default.UseEncryption)
                {
                    // Assigns the in-memory public key for this client session
                    LocalUser.PublicKeyBase64 = EncryptionHelper.PublicKeyBase64;
                    ClientLogger.ClientLog("Uses in-memory RSA public key for this session.", ClientLogLevel.Debug);

                    // Publishes the public key to the server for the handshake
                    _server.SendPublicKeyToServer(LocalUser.UID, LocalUser.PublicKeyBase64);
                    _server.RequestAllPublicKeysFromServer();

                    // Attempts encryption initialization and logs the outcome
                    if (InitializeEncryption())
                    {
                        ClientLogger.ClientLog("Encryption initialized on startup.", ClientLogLevel.Info);
                    }
                    else
                    {
                        ClientLogger.ClientLog("Encryption initialization failed on startup.", ClientLogLevel.Error);
                    }

                    // Ensures all peers are synced by re-sending and re-requesting keys
                    _server.ResendPublicKey();
                    _server.RequestAllPublicKeysFromServer();
                }

                // Updates UI to connected state
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        mainWindow.Title += " - " + LocalizationManager.GetString("Connected");
                        mainWindow.CmdConnectDisconnect.Content = "_Disconnect";
                        mainWindow.SpnDown.Visibility = Visibility.Visible;
                        mainWindow.SpnEmojiPanel.Visibility = Visibility.Visible;
                        mainWindow.TxtMessageToSend.Focus();
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
        /// Model E: Handles a decrypted chat message event (opcode 11).
        /// Appends the provided pre-formatted text to the Messages collection
        /// on the UI thread.
        /// </summary>
        /// <param name="messageToDisplay">
        /// The decrypted and formatted message (e.g. "Alice: Hello!").
        /// </param>
        public void EncryptedMessageReceived(string messageToDisplay)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                Messages.Add(messageToDisplay);
            });
        }

        /// <summary>
        /// Determines whether encryption is ready and logs the result.
        /// </summary>
        /// <returns>True if encryption is enabled and all peer public keys are received; otherwise false.</returns>
        public bool EvaluateEncryptionState()
        {
            bool ready = Settings.Default.UseEncryption && AreAllKeysReceived();
            ClientLogger.ClientLog($"EvaluateEncryptionState called — Ready: {ready}", ClientLogLevel.Debug);
            return ready;
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
        /// Executes the complete encryption setu:
        /// Skips if no LocalUser is set or encryption is already active.  
        /// Clears all stale peer public key data.  
        /// Clears local key material from memory.  
        /// Generates a new RSA key pair, registers it locally, and publishes the public key to the server.  
        /// Synchronizes peer public keys, requesting missing ones if necessary.  
        /// Recalculates encryption readiness and updates the UI lock icon if ready.  
        /// Persists handshake keys and the encryption flag to application settings.  
        /// </summary>
        /// <returns>True if encryption is successfully initialized and ready; false otherwise.</returns>
        public bool InitializeEncryption()
        {
            // Skips if no LocalUser is set or encryption is already active
            if (LocalUser == null || EncryptionHelper.IsEncryptionActive)
            {
                ClientLogger.ClientLog("Skips encryption initialization — LocalUser is null or encryption already active.",
                    ClientLogLevel.Debug);
                return false;
            }

            try
            {
                // Clears all stale peer public key data
                KnownPublicKeys.Clear();

                // Clears local key material from memory
                LocalUser.PublicKeyBase64 = string.Empty;
                LocalUser.PrivateKeyBase64 = string.Empty;
                EncryptionHelper.ClearPrivateKey();
                ClientLogger.ClientLog("Clears all previous key state.", ClientLogLevel.Debug);

                // Generates a new RSA key pair, registers it, and publishes the public key
                using var rsa = new RSACryptoServiceProvider(2048);
                string publicKeyXml = rsa.ToXmlString(false);
                string privateKeyXml = rsa.ToXmlString(true);
                string publicKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyXml));
                string privateKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyXml));

                LocalUser.PublicKeyBase64 = publicKeyBase64;
                LocalUser.PrivateKeyBase64 = privateKeyBase64;
                ClientLogger.ClientLog($"Generates RSA key pair for UID {LocalUser.UID}.", ClientLogLevel.Debug);

                lock (KnownPublicKeys)
                {
                    KnownPublicKeys[LocalUser.UID] = publicKeyBase64;
                    ClientLogger.ClientLog($"Registers local public key for UID {LocalUser.UID}.", ClientLogLevel.Debug);
                }

                bool publishedSuccessfully = _server.SendPublicKeyToServer(LocalUser.UID, publicKeyBase64);
                if (!publishedSuccessfully)
                {
                    ClientLogger.ClientLog("Fails to send public key to server — aborts encryption setup.", ClientLogLevel.Error);
                    MessageBox.Show(
                        LocalizationManager.GetString("SendingClientsPublicRSAKeyToTheServerFailed"),
                        LocalizationManager.GetString("Error"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                    Properties.Settings.Default.UseEncryption = false;
                    return false;
                }

                Properties.Settings.Default.UseEncryption = true;
                ClientLogger.ClientLog("Enables encryption in application settings.", ClientLogLevel.Info);

                // Synchronizes peer public keys and aborts on failure
                if (!SyncKeys())
                {
                    ClientLogger.ClientLog("Peer key synchronization failed — aborts encryption setup.", ClientLogLevel.Error);
                    return false;
                }

                // Recalculates encryption readiness and updates UI if ready
                bool isEncryptionReady = EvaluateEncryptionState();
                OnPropertyChanged(nameof(IsEncryptionReady));
                if (isEncryptionReady)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                        (Application.Current.MainWindow as MainWindow)
                            ?.UpdateEncryptionStatusIcon(isEncryptionReady));
                    ClientLogger.ClientLog("Updates lock icon to reflect encryption readiness.",
                        ClientLogLevel.Info);
                }

                return isEncryptionReady;
            }
            catch (Exception ex)
            {
                Properties.Settings.Default.UseEncryption = false;
                ClientLogger.ClientLog($"Exception during encryption initialization: {ex.Message}", ClientLogLevel.Error);
                return false;
            }
            finally
            {
                // Persists handshake keys and the encryption flag to settings
                Properties.Settings.Default.HandshakePublicKey = LocalUser?.PublicKeyBase64;
                Properties.Settings.Default.HandshakePrivateKey = LocalUser?.PrivateKeyBase64;
                Properties.Settings.Default.Save();
                ClientLogger.ClientLog("Persists handshake keys and encryption flag.", ClientLogLevel.Debug);
            }
        }

        /// <summary>
        /// Handles a delivered plain‐text message.
        /// Appends the provided formatted message to the chat UI on the dispatcher thread.
        /// </summary>
        /// <param name="messageToDisplay">
        /// The ready-to-display message string 
        /// </param>
        public void PlainMessageReceived(string messageToDisplay)
        {
            try
            {
                // Marshals the update to the UI thread and adds the message
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Messages.Add(messageToDisplay);
                });
            }
            catch (Exception ex)
            {
                // Logs any unexpected error during UI update
                ClientLogger.ClientLog($"PlainMessageReceived handler failed: {ex.Message}",
                    ClientLogLevel.Error);
            }
        }


        /// <summary>
        /// Model D: Handles a received public‐key event.
        /// Validates input, updates the KnownPublicKeys dictionary in a thread-safe manner,
        /// logs whether the key was added, updated, or duplicated,
        /// re-evaluates encryption readiness,
        /// and refreshes the UI lock icon if the client becomes ready.
        /// </summary>
        /// <param name="senderUid">The UID of the peer who provided the public key.</param>
        /// <param name="publicKeyBase64">The Base64-encoded RSA public key.</param>
        public void PublicKeyReceived(string senderUid, string publicKeyBase64)
        {
            // Discard if either UID or key is missing
            if (string.IsNullOrWhiteSpace(senderUid) || string.IsNullOrWhiteSpace(publicKeyBase64))
            {
                ClientLogger.ClientLog("Discarded public key: missing UID or key.",
                    ClientLogLevel.Warn);
                return;
            }

            bool isNewOrUpdated = false;

            // Protects the dictionary from concurrent writes
            lock (KnownPublicKeys)
            {
                if (KnownPublicKeys.TryGetValue(senderUid, out var existingKey))
                {
                    if (existingKey == publicKeyBase64)
                    {
                        ClientLogger.ClientLog($"Duplicate public key for {senderUid}; no change.",
                            ClientLogLevel.Debug);
                    }
                    else
                    {
                        KnownPublicKeys[senderUid] = publicKeyBase64;
                        isNewOrUpdated = true;
                        ClientLogger.ClientLog($"Updated public key for {senderUid}.",
                            ClientLogLevel.Info);
                    }
                }
                else
                {
                    KnownPublicKeys.Add(senderUid, publicKeyBase64);
                    isNewOrUpdated = true;
                    ClientLogger.ClientLog($"Registered new public key for {senderUid}.",
                        ClientLogLevel.Info);
                }
            }

            // Re-evaluates overall encryption state
            EvaluateEncryptionState();

            // Refreshes the UI lock icon if this key makes encryption fully ready
            if (isNewOrUpdated && IsEncryptionReady)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    (Application.Current.MainWindow as MainWindow)
                        ?.UpdateEncryptionStatusIcon(IsEncryptionReady);
                });
                ClientLogger.ClientLog($"Encryption readiness confirmed after registering key for {senderUid}.",
                    ClientLogLevel.Debug);
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
                        TaskbarIcon? trayIcon = mainWindow.TryFindResource("TrayIcon") as TaskbarIcon;
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
                    mainWindow.CmdConnectDisconnect.Content = LocalizationManager.GetString("ConnectButton");

                    mainWindow.TxtUsername.IsEnabled = true;
                    mainWindow.TxtIPAddress.IsEnabled = true;
                    mainWindow.Title = "WPF chat client";

                    // Hides the down and toolbar panels
                    mainWindow.SpnDown.Visibility = Visibility.Hidden;
                    mainWindow.SpnEmojiPanel.Visibility = Visibility.Hidden;
                }
            });
        }

        /// <summary>
        /// Model F: Handles a server-initiated disconnect command (opcode 12).
        /// Disconnects from the server, clears the user list, posts a localized system message,
        /// and notifies the UI that the connection status changed.
        /// </summary>
        public void ServerDisconnectedClient()
        {
            // Attempts to close the connection
            try
            {
                _server.DisconnectFromServer();
            }
            catch (Exception ex)
            {
                ClientLogger.ClientLog($"Error during server-initiated disconnect: {ex.Message}",
                    ClientLogLevel.Error);
            }

            // Executes UI-bound updates on the dispatcher thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                Users.Clear();
                Messages.Add(
                    $"# {LocalizationManager.GetString("ServerDisconnected")} #");
                OnPropertyChanged(nameof(IsConnected));
            });
        }

        /// <summary>
        /// Applies a red border style to the username textbox to visually indicate invalid input.
        /// </summary>
        private static void ShowUsernameError()
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                if (Application.Current.MainWindow is MainWindow mainWindow)
                {
                    mainWindow.TxtUsername.Style = mainWindow.TryFindResource("ErrorTextBoxStyle") as Style;
                    mainWindow.TxtUsername.Focus();
                }
            });
        }

        /// <summary>
        /// Attempts to synchronize public keys with connected peers:
        /// Verifies that encryption is enabled and context objects are initialized.  
        /// Builds a snapshot of peer UIDs to avoid concurrent collection issues.  
        /// Returns true immediately if no peers are connected.  
        /// Identifies missing keys under a thread-safe lock.  
        /// Requests a resend of the local public key for any missing entries.  
        /// Re-evaluates encryption state.  
        /// Updates the UI lock icon on the Dispatcher thread with current readiness and syncing status.  
        /// Wraps all steps in exception handling to prevent client crashes.
        /// </summary>
        /// <returns>True if synchronization completes without error; false otherwise.</returns>
        public bool SyncKeys()
        {
            try
            {
                // Verifies that encryption is enabled and context objects are initialized
                if (!Settings.Default.UseEncryption || Users == null || LocalUser == null)
                    return false;

                // Builds a snapshot of peer UIDs, excluding the local client
                var localGuid = LocalUser.UID;
                var peerUids = Users
                    .Where(u => u.UID != localGuid)
                    .Select(u => u.UID)
                    .ToList();

                // Returns true immediately if no peers are connected
                if (peerUids.Count == 0)
                {
                    EvaluateEncryptionState();
                    return true;
                }

                // Identifies missing keys under a thread-safe lock
                List<string> missingKeys;
                lock (KnownPublicKeys)
                {
                    missingKeys = peerUids
                        .Where(uid => !KnownPublicKeys.ContainsKey(uid))
                        .ToList();
                }

                // Requests a resend for any missing keys
                if (missingKeys.Count > 0)
                {
                    ClientLogger.ClientLog($"SyncKeys detected missing keys for: {string.Join(", ", missingKeys)}",
                        ClientLogLevel.Debug);
                    try
                    {
                        _server.ResendPublicKey();
                        ClientLogger.ClientLog("Requested resend of local public key from server.",
                            ClientLogLevel.Debug);
                    }
                    catch (Exception exRequest)
                    {
                        ClientLogger.ClientLog($"Failed to request public key resend: {exRequest.Message}",
                            ClientLogLevel.Error);
                    }
                }

                // Re-evaluates encryption state
                EvaluateEncryptionState();

                // Updates the lock icon on the UI thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    (Application.Current.MainWindow as MainWindow)
                        ?.UpdateEncryptionStatusIcon(
                            IsEncryptionReady,
                            missingKeys.Count > 0);
                });

                // Returns true on successful synchronization
                return true;
            }
            catch (Exception ex)
            {
                // Catches any unexpected error to prevent client termination
                ClientLogger.ClientLog($"Unexpected error in SyncKeys: {ex.Message}",
                    ClientLogLevel.Error);
                return false;
            }
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
            ClientLogger.ClientLog("TryDecryptMessage called.", ClientLogLevel.Debug);

            if (!Settings.Default.UseEncryption)
            {
                ClientLogger.ClientLog("Encryption is disabled in application settings.", ClientLogLevel.Warn);
                return LocalizationManager.GetString("DecryptionFailed");
            }

            if (string.IsNullOrWhiteSpace(encryptedPayload))
            {
                ClientLogger.ClientLog("Encrypted payload is null or empty.", ClientLogLevel.Warn);
                return LocalizationManager.GetString("DecryptionFailed");
            }

            try
            {
                ClientLogger.ClientLog($"Raw encrypted payload: {encryptedPayload}", ClientLogLevel.Debug);

                // Sanitizes payload: strips control chars and trims whitespace.
                string sanitized = encryptedPayload
                    .Replace("\0", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();
                ClientLogger.ClientLog($"Sanitized encrypted payload: {sanitized}", ClientLogLevel.Debug);

                // Delegates to EncryptionHelper for the actual decrypt.
                string result = EncryptionHelper.DecryptMessage(sanitized);
                ClientLogger.ClientLog($"Decryption successful. Decrypted message: {result}", ClientLogLevel.Debug);

                return result;
            }
            catch (Exception ex)
            {
                ClientLogger.ClientLog($"Exception during decryption: {ex.Message}", ClientLogLevel.Error);
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
                    ClientLogger.ClientLog($"User in list of users — UID: {user.UID}, HasKey: {hasKey}", ClientLogLevel.Debug);
                }
            }

            // Logs the readiness state before updating the icon
            ClientLogger.ClientLog($"UpdateEncryptionStatusIcon called — isReady: {IsEncryptionReady}", ClientLogLevel.Debug);

            // Delegates icon update to the UI layer
            (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady);

            // Logs summary of list of users and key distribution
            int userCount = Users?.Count ?? 0;
            int keyCount = KnownPublicKeys?.Count ?? 0;
            ClientLogger.ClientLog($"Encryption status updated — Users: {userCount}, Keys: {keyCount}, Ready: {IsEncryptionReady}", ClientLogLevel.Debug);
        }

        /// <summary>
        /// Model A: Handles a new user join event.
        /// Reads the provided UID, username, and public key.
        /// Adds the user to the Users collection if not already present.
        /// Registers the user’s public key and re-evaluates encryption state.
        /// Posts a system notice to the chat UI on the dispatcher thread.
        /// </summary>
        /// <param name="uid">The joining user’s unique identifier.</param>
        /// <param name="username">The joining user’s display name.</param>
        /// <param name="publicKey">The joining user’s RSA public key (base64).</param>
        public void UserConnected(string uid, string username, string publicKey)
        {
            // Prevents duplicates
            if (Users.Any(u => u.UID == uid))
                return;

            // Builds the new user model
            var user = new UserModel
            {
                UID = uid,
                Username = username,
                PublicKeyBase64 = publicKey
            };

            // Invokes all UI-bound updates on the main thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                // Adds the new user to the observable collection
                Users.Add(user);

                // Updates the expected client count and logs the change
                ExpectedClientCount = Users.Count;
                ClientLogger.ClientLog($"ExpectedClientCount updated — Total users: {ExpectedClientCount}",
                    ClientLogLevel.Debug);

                // Registers the public key if not already known
                if (!KnownPublicKeys.ContainsKey(uid))
                {
                    KnownPublicKeys[uid] = publicKey;
                    ClientLogger.ClientLog($"Public key registered for {username} — UID: {uid}",
                        ClientLogLevel.Debug);
                }

                // Re-evaluates whether encryption features can be enabled
                EvaluateEncryptionState();

                // Posts a system notice to the chat window
                Messages.Add(
                    $"# {username} {LocalizationManager.GetString("HasConnected")} #");
            });
        }

        /// <summary>
        /// Model A: Handles a user disconnect event (opcode 10).
        /// Removes the specified user from the Users list,
        /// posts a localized system notice to the chat,
        /// updates the expected client count,
        /// and re-evaluates encryption readiness if enabled.
        /// </summary>
        /// <param name="uid">The UID of the user who disconnected.</param>
        /// <param name="username">The display name of the user who disconnected.</param>
        public void UserDisconnected(string uid, string username)
        {
            try
            {
                // Locates the user by UID
                var user = Users.FirstOrDefault(u => u.UID == uid);
                if (user == null)
                    return;

                // Updates UI-bound state on the dispatcher thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    // Removes the disconnected user
                    Users.Remove(user);

                    // Updates and logs the expected client count
                    ExpectedClientCount = Users.Count;
                    ClientLogger.ClientLog($"ExpectedClientCount updated — Total users: {ExpectedClientCount}",
                        ClientLogLevel.Debug);

                    // Posts a system message indicating the disconnection
                    Messages.Add(
                        $"# {username} {LocalizationManager.GetString("HasDisconnected")} #");

                    // Re-evaluates encryption readiness if encryption is active
                    if (chat_client.Properties.Settings.Default.UseEncryption)
                    {
                        EvaluateEncryptionState();
                    }

                    ClientLogger.ClientLog($"User disconnected — Username: {username}, UID: {uid}",
                        ClientLogLevel.Debug);
                });
            }
            catch (Exception ex)
            {
                // Logs any unexpected error in the handler
                ClientLogger.ClientLog($"UserDisconnected handler failed: {ex.Message}",  ClientLogLevel.Error);
            }
        }
    }
}
