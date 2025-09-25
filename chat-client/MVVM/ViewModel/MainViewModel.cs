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
        /// Gets whether encryption is currently synchronizing peer public keys.
        /// Returns true when encryption is enabled but not all keys have been received.
        /// </summary>
        public bool IsEncryptionSyncing
        {
            get => Settings.Default.UseEncryption && !AreAllKeysReceived();
        }

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
        /// Determines whether encryption can proceed by checking:
        ///   1. Encryption is enabled in settings  
        ///   2. Local user and its public key are initialized  
        ///   3. All connected peers have published a valid public key  
        /// Uses a lock on the shared key dictionary to ensure thread safety
        /// and logs each decision point for detailed troubleshooting.
        /// </summary>
        /// <returns>True if encryption is fully ready (including solo mode); otherwise, false.</returns>
        public bool AreAllKeysReceived()
        {
            // Logs the current encryption setting for debugging
            ClientLogger.Log(
                $"Checking encryption readiness — UseEncryption={Settings.Default.UseEncryption}",
                LogLevel.Debug);

            // Skips if encryption is disabled or if the local user is not initialized
            if (!Settings.Default.UseEncryption || LocalUser == null)
            {
                ClientLogger.Log(
                    "Skipping encryption readiness check — encryption disabled or local user not initialized.",
                    LogLevel.Info);
                return false;
            }

            // Checks presence of the local public key
            bool hasLocalKey = !string.IsNullOrEmpty(LocalUser.PublicKeyBase64);
            ClientLogger.Log(
                $"Local public key present: {hasLocalKey}",
                LogLevel.Debug);

            if (!hasLocalKey)
            {
                ClientLogger.Log(
                    "Skipping encryption readiness check — local public key not yet generated.",
                    LogLevel.Info);
                return false;
            }

            // Handles solo mode where no peers are connected
            if (Users.Count == 0)
            {
                ClientLogger.Log(
                    "Solo mode detected — no peers; encryption considered ready.",
                    LogLevel.Debug);

                ClientLogger.Log(
                    "Encryption is fully activated and ready (solo mode).",
                    LogLevel.Info);
                return true;
            }

            List<string> missingKeys;

            // Locks the shared dictionary while computing missing entries
            lock (KnownPublicKeys)
            {
                var peerUids = Users.Select(u => u.UID).ToList();
                ClientLogger.Log(
                    $"Peer UIDs to verify: {string.Join(", ", peerUids)}",
                    LogLevel.Debug);

                missingKeys = peerUids
                    .Except(KnownPublicKeys.Keys)
                    .ToList();

                ClientLogger.Log(
                    $"Number of missing keys detected: {missingKeys.Count}",
                    LogLevel.Debug);
            }

            // Logs and aborts if any peer keys are missing
            if (missingKeys.Any())
            {
                ClientLogger.Log(
                    $"Encryption not ready — missing keys for: {string.Join(", ", missingKeys)}",
                    LogLevel.Debug);
                return false;
            }

            // All checks passed: logs activation and returns readiness
            ClientLogger.Log(
                "Encryption is fully activated and ready.",
                LogLevel.Info);
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
                    // Assigns the in-memory public key for this client session
                    LocalUser.PublicKeyBase64 = EncryptionHelper.PublicKeyBase64;
                    ClientLogger.Log("Uses in-memory RSA public key for this session.", LogLevel.Debug);

                    // Publishes the public key to the server for the handshake
                    Server.SendPublicKeyToServer(LocalUser.UID, LocalUser.PublicKeyBase64);
                    _server.RequestAllPublicKeysFromServer();

                    // Initializes the local encryption helpers for message processing
                    InitializeEncryption(this);
                    ClientLogger.Log("Encryption initialized on startup.", LogLevel.Info);

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
        /// Recalculates the overall encryption state in a thread-safe, single-notification manner.
        /// Determines readiness by verifying encryption settings, local key presence, and peer key availability.
        /// Updates the IsEncryptionReady property (whose setter raises change notifications 
        /// for both readiness and syncing exactly once), and logs the result for debugging.
        /// This method is invoked whenever user lists or key collections change.
        /// </summary>
        public void EvaluateEncryptionState()
        {
            // Determines whether all required public keys are now present
            bool ready = AreAllKeysReceived();

            // Updates the readiness flag;
            // the setter raises PropertyChanged for both IsEncryptionReady and IsEncryptionSyncing exactly once
            IsEncryptionReady = ready;

            // Logs the new encryption state for traceability
            ClientLogger.Log(
                $"EvaluateEncryptionState called — Ready: {IsEncryptionReady}",
                LogLevel.Debug);
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
        /// Initializes RSA encryption for the current session in a thread-safe, idempotent manner.
        /// 1. Verifies that a local user exists and that encryption is not already active.
        /// 2. Generates a new 2048-bit RSA key pair.
        /// 3. Encodes the public and private keys in Base64 and stores them on the LocalUser model.
        /// 4. Locks the KnownPublicKeys dictionary and registers the user’s own public key locally.
        /// 5. Sends the public key to the server for distribution to all peers.
        /// 6. Marks encryption as enabled in the client settings upon successful transmission.
        /// 7. Imports any pre-existing peer keys from the provided ViewModel under lock.
        /// 8. If the known-key count is incomplete, requests the server to resend all public keys.
        /// 9. Recalculates encryption readiness and logs the result (without touching the UI).
        /// 10. Performs one final SyncKeys pass to recover any missing keys.
        /// 11. Saves the handshake key pair and encryption flag to persistent settings in one atomic call,
        ///     then updates the UI lock-icon to reflect ultimate encryption readiness.
        /// All steps log progress or errors and catch exceptions to prevent the client from crashing.
        /// </summary>
        /// <param name="viewModel">The MainViewModel providing context and peer key retrieval.</param>
        /// <returns>True if encryption was initialized successfully; otherwise, false.</returns>
        public bool InitializeEncryption(MainViewModel viewModel)
        {
            // 1. Skips if no user or encryption already active
            if (LocalUser == null || EncryptionHelper.IsEncryptionActive)
            {
                ClientLogger.Log(
                    "Encryption initialization skipped — no LocalUser or already active.",
                    LogLevel.Debug);
                return false;
            }

            bool initializationSucceeded = false;

            try
            {
                // 2. Generates a new 2048-bit RSA key pair
                using var rsa = new RSACryptoServiceProvider(2048);
                string publicKeyXml = rsa.ToXmlString(false);
                string privateKeyXml = rsa.ToXmlString(true);

                // 3. Encodes keys in Base64
                string publicKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyXml));
                string privateKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyXml));

                // Stores Base64 keys in LocalUser
                LocalUser.PublicKeyBase64 = publicKeyBase64;
                LocalUser.PrivateKeyBase64 = privateKeyBase64;
                ClientLogger.Log(
                    $"RSA key pair generated for UID {LocalUser.UID}.",
                    LogLevel.Debug);

                // 4. Registers own public key locally under lock
                lock (KnownPublicKeys)
                {
                    KnownPublicKeys[LocalUser.UID] = publicKeyBase64;
                    ClientLogger.Log(
                        $"Local public key added to KnownPublicKeys for UID {LocalUser.UID}.",
                        LogLevel.Debug);
                }

                // 5. Sends public key to server
                bool sent = Server.SendPublicKeyToServer(LocalUser.UID, publicKeyBase64);
                if (!sent)
                {
                    ClientLogger.Log(
                        "Failed to send public key to server — disabling encryption.",
                        LogLevel.Error);
                    MessageBox.Show(
                        LocalizationManager.GetString("SendingClientsPublicRSAKeyToTheServerFailed"),
                        LocalizationManager.GetString("Error"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);

                    Properties.Settings.Default.UseEncryption = false;
                    return false;
                }

                // 6. Enables encryption in settings
                Properties.Settings.Default.UseEncryption = true;
                initializationSucceeded = true;
                ClientLogger.Log(
                    "Encryption enabled in application settings.",
                    LogLevel.Info);

                // 7. Imports peer keys from ViewModel under lock
                lock (KnownPublicKeys)
                {
                    foreach (var (peerUid, peerKey) in viewModel.GetAllKnownPublicKeys())
                    {
                        if (!KnownPublicKeys.ContainsKey(peerUid))
                        {
                            KnownPublicKeys[peerUid] = peerKey;
                            ClientLogger.Log(
                                $"Imported external public key for peer UID {peerUid}.",
                                LogLevel.Debug);
                        }
                    }
                }

                // 8. Requests full key sync if set is incomplete
                if (KnownPublicKeys.Count < viewModel.ExpectedClientCount)
                {
                    _server.RequestAllPublicKeysFromServer();
                    ClientLogger.Log(
                        "Requested full public-key synchronization from server.",
                        LogLevel.Debug);
                }

                // 9. Recalculates readiness (logs only, no UI update)
                EvaluateEncryptionState();
                ClientLogger.Log(
                    $"Post-init readiness: {IsEncryptionReady} with {KnownPublicKeys.Count}/{viewModel.ExpectedClientCount} keys.",
                    LogLevel.Debug);

                // 10. Performs final synchronization pass
                SyncKeys();

                return true;
            }
            catch (Exception ex)
            {
                // Disables encryption on exception to keep client stable
                Properties.Settings.Default.UseEncryption = false;
                ClientLogger.Log(
                    $"Exception during encryption initialization: {ex.Message}",
                    LogLevel.Error);
                return false;
            }
            finally
            {
                // 11. Persists handshake keys and encryption flag in one atomic save
                Properties.Settings.Default.HandshakePublicKey = LocalUser?.PublicKeyBase64;
                Properties.Settings.Default.HandshakePrivateKey = LocalUser?.PrivateKeyBase64;
                Properties.Settings.Default.Save();
                ClientLogger.Log(
                    "Handshake keys and encryption settings persisted.",
                    LogLevel.Debug);

                // Only now updates the UI lock-icon if initialization succeeded
                if (initializationSucceeded)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        (Application.Current.MainWindow as MainWindow)
                            ?.UpdateEncryptionStatusIcon(IsEncryptionReady);
                    });
                    ClientLogger.Log(
                        "UI lock-icon updated to reflect final encryption readiness.",
                        LogLevel.Info);
                }
            }
        }

        /// <summary>
        /// Executes the full encryption activation cycle end-to-end:
        /// 1. Clears any stale local and peer key state.
        /// 2. Generates a fresh RSA key pair and stores it on LocalUser.
        /// 3. Sends the public key to the server for distribution.
        /// 4. Marks encryption enabled in settings.
        /// 5. Imports any keys already known on startup.
        /// 6. Requests missing keys from server and synchronizes peer keys.
        /// 7. Recalculates readiness and returns true only if all keys are present.
        /// </summary>
        /// <returns>
        /// True if encryption was successfully initialized and is fully ready (colored lock-icon);
        /// false if any step failed (toggle rollback possible).
        /// </returns>
        public bool InitializeEncryptionFull()
        {
            // 1. Clear stale key material
            KnownPublicKeys.Clear();
            LocalUser.PublicKeyBase64 = null;
            LocalUser.PrivateKeyBase64 = null;
            EncryptionHelper.ClearPrivateKey();
            ClientLogger.Log("Cleared all previous key state.", LogLevel.Debug);

            // 2–6. Delegates to existing InitializeEncryption() for core RSA generation + server publish
            bool coreOk = InitializeEncryption(this);
            if (!coreOk)
            {
                ClientLogger.Log("Core InitializeEncryption() failed.", LogLevel.Error);
                return false;
            }

            // 7. Ensures peer keys are fetched and ready
            SyncKeys();

            // 8. Final evaluation: IsEncryptionReady true only if all keys received
            EvaluateEncryptionState();

            ClientLogger.Log($"InitializeEncryptionFull completed — Ready: {IsEncryptionReady}",
                IsEncryptionReady ? LogLevel.Info : LogLevel.Warn);

            return IsEncryptionReady;
        }

        /// <summary>
        /// Processes incoming chat packets (opcode 5) in a safe and robust manner.  
        /// Reads the sender UID, recipient UID, and raw content sequentially from the packet reader.  
        /// Filters out unicast messages not addressed to this client.  
        /// Handles system disconnect commands immediately.  
        /// Detects encrypted payloads by the “[ENC]” prefix, sanitizes control characters,  
        /// and attempts decryption inside a guarded block to prevent exceptions from crashing the client.  
        /// Falls back to a localized error message if decryption fails.  
        /// Resolves the sender’s display name from the user list or falls back to UID.  
        /// Finally, marshals the formatted message onto the UI thread to update the Messages collection.
        /// </summary>
        private void MessageReceived()
        {
            try
            {
                // Reads the UID of the sender from the incoming packet
                string senderUid = _server.PacketReader.ReadMessage();

                // Reads the UID of the intended recipient (empty = broadcast)
                string recipientUid = _server.PacketReader.ReadMessage();

                // Reads the raw content, which may include an “[ENC]” prefix
                string rawContent = _server.PacketReader.ReadMessage();

                // Filters out unicast messages not intended for this client
                if (!string.IsNullOrEmpty(recipientUid)
                    && recipientUid != LocalUser.UID)
                {
                    return;
                }

                // Handles system-issued disconnect commands immediately
                if (rawContent == "/disconnect"
                    && senderUid == SystemUID.ToString())
                {
                    HandleSystemDisconnect();
                    return;
                }

                // Determines the display name: looks up the user or falls back to UID
                string displayName = Users
                    .FirstOrDefault(u => u.UID.ToString() == senderUid)?.Username
                    ?? (LocalUser?.UID == senderUid ? LocalUser.Username
                                                     : senderUid);

                string finalMessage;

                // Detects and processes encrypted payloads
                if (rawContent.StartsWith("[ENC]"))
                {
                    // Strips the “[ENC]” marker and removes stray control characters
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
                    catch (Exception exDecrypt)
                    {
                        // Logs decryption errors and uses a localized fallback message
                        ClientLogger.Log(
                            $"Decryption error for sender {senderUid}: {exDecrypt.Message}",
                            LogLevel.Error);
                        string errorText = LocalizationManager.GetString("DecryptionFailed");
                        finalMessage = $"{displayName}: {errorText}";
                    }
                }
                else
                {
                    // Uses the raw content for plain-text messages
                    finalMessage = $"{displayName}: {rawContent}";
                }

                // Marshals the formatted message onto the UI thread safely
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Messages.Add(finalMessage);
                });
            }
            catch (Exception ex)
            {
                // Catches any unexpected exception to prevent client termination
                ClientLogger.Log(
                    $"Unexpected error in MessageReceived: {ex.Message}",
                    LogLevel.Error);
            }
        }

        /// <summary>
        /// Registers or updates a peer’s RSA public key in a thread-safe, idempotent manner.
        /// Locks the shared key dictionary to prevent concurrent writes, logs whether a key was added, updated, or duplicated,
        /// re-evaluates overall encryption readiness, and refreshes the lock icon if encryption becomes fully ready.
        /// </summary>
        /// <param name="uid">The unique identifier of the peer.</param>
        /// <param name="publicKeyBase64">The Base64-encoded RSA public key.</param>
        public void ReceivePublicKey(string uid, string publicKeyBase64)
        {
            // Guard against invalid input
            if (string.IsNullOrWhiteSpace(uid) || string.IsNullOrWhiteSpace(publicKeyBase64))
            {
                ClientLogger.Log(
                    $"Discarded incoming public key — uid or key is empty.",
                    LogLevel.Warn);
                return;
            }

            bool isNewOrUpdated = false;

            // Protects KnownPublicKeys from concurrent access
            lock (KnownPublicKeys)
            {
                if (KnownPublicKeys.TryGetValue(uid, out var existingKey))
                {
                    // Detects duplicate key receipt
                    if (existingKey == publicKeyBase64)
                    {
                        ClientLogger.Log(
                            $"Received duplicate public key for UID {uid}; no change.",
                            LogLevel.Debug);
                    }
                    else
                    {
                        // Updates changed key
                        KnownPublicKeys[uid] = publicKeyBase64;
                        isNewOrUpdated = true;
                        ClientLogger.Log(
                            $"Updated public key for UID {uid}.",
                            LogLevel.Info);
                    }
                }
                else
                {
                    // Adds new key
                    KnownPublicKeys.Add(uid, publicKeyBase64);
                    isNewOrUpdated = true;
                    ClientLogger.Log(
                        $"Registered new public key for UID {uid}.",
                        LogLevel.Info);
                }
            }

            // Re-evaluates encryption state, raising PropertyChanged for readiness and syncing
            EvaluateEncryptionState();

            // If encryptions just became ready, update the UI lock icon
            if (IsEncryptionReady && isNewOrUpdated)
            {
                (Application.Current.MainWindow as MainWindow)
                    ?.UpdateEncryptionStatusIcon(IsEncryptionReady);
                ClientLogger.Log(
                    $"Encryption readiness confirmed after key registration for UID {uid}.",
                    LogLevel.Debug);
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
        /// Ensures that all connected peers have published their RSA public keys.
        /// If any keys are missing, requests the server to resend the local public key.
        /// Re-evaluates encryption readiness (both ready and syncing flags),
        /// and refreshes the lock-icon on the UI with the current sync status.
        /// Wraps all operations in thread-safe locks and exception handlers to prevent client crashes.
        /// </summary>
        public void SyncKeys()
        {
            try
            {
                // Skips synchronization if encryption is disabled or if Users or LocalUser is uninitialized
                if (!Settings.Default.UseEncryption || Users == null || LocalUser == null)
                    return;

                // Builds a snapshot of peer UIDs (excludes self) to avoid concurrent collection issues
                var peerUids = Users
                    .Where(u => u.UID != LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                // If no peers exist, triggers a readiness re-evaluation and exits
                if (peerUids.Count == 0)
                {
                    EvaluateEncryptionState();
                    return;
                }

                List<string> missingKeys;

                // Locks the shared dictionary while checking for missing entries
                lock (KnownPublicKeys)
                {
                    missingKeys = peerUids
                        .Where(uid => !KnownPublicKeys.ContainsKey(uid))
                        .ToList();
                }

                // If any keys are missing, logs the UIDs and requests a key resend
                if (missingKeys.Count > 0)
                {
                    ClientLogger.Log(
                        $"SyncKeys detected missing keys for: {string.Join(", ", missingKeys)}",
                        LogLevel.Debug);

                    try
                    {
                        _server.ResendPublicKey();
                        ClientLogger.Log(
                            "Requests resend of local public key from server.",
                            LogLevel.Debug);
                    }
                    catch (Exception exRequest)
                    {
                        ClientLogger.Log(
                            $"Failed to request public key resend: {exRequest.Message}",
                            LogLevel.Error);
                    }
                }

                // Re-evaluates encryption state, raising PropertyChanged for ready and syncing
                EvaluateEncryptionState();

                // Updates the lock icon on the UI thread with the current ready/syncing status
                Application.Current.Dispatcher.Invoke(() =>
                {
                    (Application.Current.MainWindow as MainWindow)
                        ?.UpdateEncryptionStatusIcon(
                            IsEncryptionReady,
                            missingKeys.Count > 0);
                });
            }
            catch (Exception ex)
            {
                // Catches any unexpected error to prevent the client from terminating
                ClientLogger.Log(
                    $"Unexpected error in SyncKeys: {ex.Message}",
                    LogLevel.Error);
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
