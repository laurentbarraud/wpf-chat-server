/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 21th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.MVVM.View;
using chat_client.Net;
using chat_client.Net.IO;
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

        // Exposes the current encryption setting (UseEncryption) as a read-only property.
        // Uses expression-bodied syntax (=>) for clarity and ensures the value is always up-to-date.
        public bool IsEncryptionEnabled => chat_client.Properties.Settings.Default.UseEncryption;

        private bool _isEncryptionReady;

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

        private bool _isConnected;

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

        /// <summary>
        /// Initializes the main view model and subscribes to server-side events.
        /// Handles user connection, message reception, and disconnection via event-driven architecture.
        /// </summary>
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
        /// Determines whether encryption can be considered fully ready for public chat.
        /// Returns true when encryption is enabled, the local public key is present,
        /// and either no list of users is available, the client is alone, or all other users have exchanged keys.
        /// Logs missing UIDs for debugging purposes.
        /// </summary>
        /// <returns>True if encryption is ready; otherwise, false.</returns>
        public bool AreAllKeysReceived()
        {
            // Encryption must be enabled
            if (!IsEncryptionEnabled)
                return false;

            // Local public key must exist
            if (string.IsNullOrEmpty(LocalUser?.PublicKeyBase64))
                return false;

            // If no list of users is available yet, consider encryption ready
            if (Users == null || Users.Count == 0)
                return true;

            // If only the local user is present, encryption is trivially ready
            if (Users.Count == 1 && Users[0].UID == LocalUser.UID)
                return true;

            // Checks that at least one external public key is known
            bool hasExternalKey = KnownPublicKeys.Any(kvp =>
                kvp.Key != LocalUser.UID && !string.IsNullOrEmpty(kvp.Value));

            if (!hasExternalKey)
            {
                Console.WriteLine("[DEBUG] Encryption not ready — no external public keys available.");
                return false;
            }

            // Tracks missing UIDs for logging
            List<string> missingKeys = new();

            // Checks that every other user has a known public key
            foreach (var user in Users)
            {
                if (user.UID == LocalUser.UID)
                    continue;

                if (!KnownPublicKeys.ContainsKey(user.UID))
                    missingKeys.Add(user.UID);
            }

            // Logs missing UIDs if any
            if (missingKeys.Count > 0)
            {
                string joined = string.Join(", ", missingKeys);
                Console.WriteLine($"[DEBUG] Encryption not ready — missing keys for: {joined}");
                return false;
            }

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
            if (!IsEncryptionEnabled)
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
        /// Initiates the client-side connection workflow with full identity synchronization.
        /// Validates the username format and delegates the TCP handshake to the Server layer.
        /// Retrieves the UID and RSA public key generated during handshake to initialize LocalUser.
        /// Ensures protocol alignment between client and server for traceable communication.
        /// Activates encryption if enabled, updates UI state, and stores connection metadata for future sessions.
        /// Designed for maintainability, auditability, and recruiter-facing clarity.
        /// </summary>
        public void Connect()
        {
            // Rejects empty or malformed usernames to prevent handshake inconsistencies
            if (string.IsNullOrWhiteSpace(Username) || !Regex.IsMatch(Username, @"^[a-zA-Z][a-zA-Z0-9_-]*$"))
            {
                // Highlights the username textbox in crimson to indicate invalid input
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
                // Initiates TCP connection and retrieves handshake identity from Server
                var result = _server.ConnectToServer(Username.Trim(), IPAddressOfServer);
                if (result.uid == Guid.Empty || string.IsNullOrEmpty(result.publicKeyBase64))
                    throw new Exception(LocalizationManager.GetString("ConnectionFailed"));

                // Initializes LocalUser with verified handshake identity
                LocalUser = new UserModel
                {
                    Username = Username.Trim(),
                    UID = result.uid.ToString(),
                    PublicKeyBase64 = result.publicKeyBase64
                };

                Console.WriteLine($"[DEBUG] LocalUser initialized — Username: {LocalUser.Username}, UID: {LocalUser.UID}");

                // Marks connection as successful
                IsConnected = true;
                Console.WriteLine("[DEBUG] Client connected — plain messages allowed before handshake.");

                // Activates encryption if enabled in application settings
                if (Properties.Settings.Default.UseEncryption)
                {
                    InitializeEncryptionIfEnabled();
                }

                // Updates UI to reflect connected state and unlocks chat features
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        mainWindow.Title += " - " + LocalizationManager.GetString("Connected");
                        mainWindow.cmdConnectDisconnect.Content = "_Disconnect";
                        mainWindow.spnDown.Visibility = Visibility.Visible;
                        mainWindow.spnEmojiPanel.Visibility = Visibility.Visible;
                    }
                });

                // Stores the last used IP address for future sessions
                chat_client.Properties.Settings.Default.LastIPAddressUsed = IPAddressOfServer;
                chat_client.Properties.Settings.Default.Save();
            }
            catch (Exception)
            {
                // Handles connection failure gracefully and resets UI state
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
        /// Evaluates the current encryption state by checking whether all required public keys are received.
        /// Updates the IsEncryptionReady property, which triggers UI updates via data binding.
        /// Should be called whenever the Users list changes or a new public key is received.
        /// </summary>
        public void EvaluateEncryptionState()
        {
            IsEncryptionReady = AreAllKeysReceived();
            Console.WriteLine($"[DEBUG] EvaluateEncryptionState called — Ready: {IsEncryptionReady}");
        }

        /// <summary>
        /// Formats an incoming encrypted message with the sender's display name.
        /// Extracts the encrypted payload, attempts decryption, and returns a formatted string.
        /// If decryption fails, returns a localized placeholder message.
        /// </summary>
        private string FormatEncryptedMessage(string rawMessage, string displayName)
        {
            try
            {
                // Extracts the encrypted payload after the [ENC] marker
                int markerIndex = rawMessage.IndexOf("[ENC]");
                string encryptedPayload = rawMessage.Substring(markerIndex + "[ENC]".Length).Trim();

                // Sanitizes the payload to remove invisible or invalid characters
                encryptedPayload = encryptedPayload
                    .Replace("\0", "")
                    .Replace("\r", "")
                    .Replace("\n", "");

                // Attempts decryption using the local private key
                string decryptedContent = TryDecryptMessage(encryptedPayload);

                // Returns the formatted decrypted message
                return $"{displayName}: {decryptedContent}";
            }
            catch
            {
                // Returns a placeholder if decryption fails
                return $"{displayName}: {LocalizationManager.GetString("DecryptionFailed")}";
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
        /// Initializes RSA encryption for the current session if enabled and all prerequisites are satisfied.
        /// - Generates a new 2048-bit RSA key pair
        /// - Encodes both keys in Base64 and stores them in the local user model
        /// - Injects the private key into the decryption helper
        /// - Sends the public key to the server for distribution
        /// - Registers the local public key in KnownPublicKeys for readiness evaluation
        /// - Triggers encryption state evaluation and updates the UI icon
        /// Includes detailed logging for debugging and traceability.
        /// Designed to be idempotent and fail-safe: skips initialization if already done or prerequisites are missing.
        /// </summary>
        /// <returns>True if encryption was successfully initialized and the key was sent; false otherwise.</returns>
        public bool InitializeEncryptionIfEnabled()
        {
            // Prevents redundant initialization if the local user is undefined or already has a public key
            if (LocalUser == null || !string.IsNullOrEmpty(LocalUser.PublicKeyBase64))
            {
                Console.WriteLine("[DEBUG] Encryption initialization skipped — LocalUser is null or already initialized.");
                return false;
            }

            try
            {
                // Generates a new RSA key pair with 2048-bit security
                using var rsa = new RSACryptoServiceProvider(2048);

                // Extracts the public key (XML format, no private parameters)
                string publicKeyXml = rsa.ToXmlString(false);

                // Extracts the private key (XML format, includes private parameters)
                string privateKeyXml = rsa.ToXmlString(true);

                // Encodes both keys in Base64 for safe transport and storage
                string publicKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyXml));
                string privateKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyXml));

                // Stores the keys in the local user model for later use
                LocalUser.PublicKeyBase64 = publicKeyBase64;
                LocalUser.PrivateKeyBase64 = privateKeyBase64;

                Console.WriteLine($"[DEBUG] RSA key pair generated — UID: {LocalUser.UID}");

                // Injects the private key into the helper class for decryption support
                EncryptionHelper.SetPrivateKey(privateKeyBase64);
                Console.WriteLine("[DEBUG] Private key injected into EncryptionHelper.");

                // Sends the public key to the server for distribution to other clients
                bool sent = Server.SendPublicKeyToServer(LocalUser.UID, publicKeyBase64);
                if (!sent)
                {
                    // Displays a localized error message to the user
                    MessageBox.Show(
                        LocalizationManager.GetString("SendingClientsPublicRSAKeyToTheServerFailed"),
                        LocalizationManager.GetString("Error"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);

                    // Rolls back encryption setting to prevent inconsistent state
                    Properties.Settings.Default.UseEncryption = false;
                    Properties.Settings.Default.Save();

                    Console.WriteLine("[ERROR] Failed to send public key to server — encryption disabled.");
                    return false;
                }

                // Marks encryption as active in persistent settings
                Properties.Settings.Default.UseEncryption = true;
                Properties.Settings.Default.Save();
                Console.WriteLine("[DEBUG] Encryption enabled in settings.");

                // Registers the local public key in KnownPublicKeys for readiness checks
                if (!string.IsNullOrEmpty(LocalUser.UID) && !string.IsNullOrEmpty(LocalUser.PublicKeyBase64))
                {
                    KnownPublicKeys[LocalUser.UID] = LocalUser.PublicKeyBase64;
                    Console.WriteLine($"[DEBUG] Local public key registered in KnownPublicKeys — UID: {LocalUser.UID}");
                }

                // Evaluates encryption readiness and updates the lock icon
                EvaluateEncryptionState();
                (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady);

                Console.WriteLine($"[DEBUG] Encryption initialization complete — Ready: {IsEncryptionReady}");
                return true;
            }
            catch (Exception ex)
            {
                // Rolls back encryption setting on failure
                Properties.Settings.Default.UseEncryption = false;
                Properties.Settings.Default.Save();

                Console.WriteLine($"[ERROR] Exception during encryption initialization: {ex.Message}");
                return false;
            }
        }


        /// <summary>
        /// Handles incoming messages from the server.
        /// Resolves sender identity from UID and displays either plain or decrypted content.
        /// Supports system-issued disconnect commands and updates the UI accordingly.
        /// Ensures robust handling of encrypted payloads and fallback in case of decryption failure.
        /// </summary>
        private void MessageReceived()
        {
            string senderUID = _server.PacketReader.ReadMessage();  // UID of sender
            string rawMessage = _server.PacketReader.ReadMessage(); // May contain plain text or [ENC]

            // Handles system-issued disconnect command
            if (rawMessage == "/disconnect" && senderUID == SystemUID.ToString())
            {
                HandleSystemDisconnect();
                return;
            }

            // Resolves sender display name from UID
            string displayName =
                Users.FirstOrDefault(u => u.UID == senderUID)?.Username ??
                (LocalUser?.UID == senderUID ? LocalUser.Username : senderUID);

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

                    // Formats and displays the decrypted message
                    string finalMessage = FormatEncryptedMessage(decryptedContent, displayName);

                    Application.Current.Dispatcher.Invoke(() => Messages.Add(finalMessage));
                }
                catch (Exception ex)
                {
                    // Displays a system message indicating decryption failure
                    string errorMessage = "# - " + LocalizationManager.GetString("DecryptionFailed") + ": " + ex.Message + " #";
                    Application.Current.Dispatcher.Invoke(() => Messages.Add(errorMessage));
                }
            }
            else
            {
                // Displays plain message with sender name
                string finalMessage = $"{displayName}: {rawMessage}";
                Application.Current.Dispatcher.Invoke(() => Messages.Add(finalMessage));
            }
        }

        /// <summary>
        /// Stores a received public RSA key and updates encryption state.
        /// Automatically re-evaluates readiness and refreshes the encryption icon.
        /// Logs key reception and current readiness status for debugging.
        /// </summary>
        /// <param name="uid">The UID of the user whose public key is received.</param>
        /// <param name="publicKeyBase64">The Base64-encoded public key.</param>
        public void ReceivePublicKey(string uid, string publicKeyBase64)
        {
            if (string.IsNullOrWhiteSpace(uid) || string.IsNullOrWhiteSpace(publicKeyBase64))
                return;

            // Stores or updates the key
            KnownPublicKeys[uid] = publicKeyBase64;

            // Re-evaluates encryption readiness
            EvaluateEncryptionState();

            // Updates the lock icon
            (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady);

            // Logs key reception and readiness status
            int keyCount = KnownPublicKeys?.Count ?? 0;
            Console.WriteLine($"[DEBUG] Public key received for UID: {uid} — Total keys: {keyCount}, Ready: {IsEncryptionReady}");
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
                    mainWindow.Title = "WPF Chat";

                    // Hides the down and toolbar panels
                    mainWindow.spnDown.Visibility = Visibility.Hidden;
                    mainWindow.spnEmojiPanel.Visibility = Visibility.Hidden;
                }
            });
        }

        /// <summary>
        /// Resends the client's public RSA key to the server for recovery or synchronization purposes.
        /// Typically called when key distribution fails or when a new client join and requires the key.
        /// Ensures that the server and all connected clients have access to the sender's encryption identity.
        /// Designed to be safe and idempotent — skips transmission if prerequisites are missing.
        /// </summary>
        public void ResendPublicKey()
        {
            // Validates prerequisites before attempting to resend
            if (LocalUser == null || string.IsNullOrEmpty(LocalUser.PublicKeyBase64))
            {
                Console.WriteLine("[WARN] Cannot resend public key — LocalUser or key is missing.");
                return;
            }

            // Sends the public key to the server for redistribution
            Server.SendPublicKeyToServer(LocalUser.UID, LocalUser.PublicKeyBase64);
            Console.WriteLine("[DEBUG] Public key resent manually.");
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
            if (!IsEncryptionEnabled || Users == null || Users.Count == 0)
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
                Console.WriteLine($"[DEBUG] Missing keys detected: {string.Join(", ", missing)}");

                // Attempts to resend the local public key to the server
                ResendPublicKey();
            }

            // Updates encryption readiness and UI icon with sync state
            bool isSyncing = missing.Count > 0;
            (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady, isSyncing);
        }

        /// <summary>
        /// Attempts to decrypt an incoming encrypted message using the local RSA private key.
        /// Validates encryption state and key readiness before proceeding.
        /// Sanitizes the encrypted payload to remove invalid characters before delegating to EncryptionHelper.
        /// Returns the decrypted plain text if successful; otherwise, returns a localized fallback string.
        /// Designed to ensure graceful failure handling and UI feedback.
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
                // Sanitizes the payload to remove invisible or invalid characters
                string sanitizedPayload = encryptedPayload
                    .Replace("\0", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();

                // Attempts decryption using the helper
                string decrypted = EncryptionHelper.DecryptMessage(sanitizedPayload);
                return decrypted;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Decryption failed: {ex.Message}");

                // Displays a banner to inform the user
                Application.Current.Dispatcher.Invoke(() =>
                {
                    var mainWindow = Application.Current.MainWindow as MainWindow;
                    mainWindow?.ShowBanner("DecryptionFailed", showIcon: true);
                });

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
                    Console.WriteLine($"[DEBUG] User in list of users — UID: {user.UID}, HasKey: {hasKey}");
                }
            }

            // Logs the readiness state before updating the icon
            Console.WriteLine($"[DEBUG] UpdateEncryptionStatusIcon called — isReady: {IsEncryptionReady}");

            // Delegates icon update to the UI layer
            (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady);

            // Logs summary of list of users and key distribution
            int userCount = Users?.Count ?? 0;
            int keyCount = KnownPublicKeys?.Count ?? 0;
            Console.WriteLine($"[DEBUG] Encryption status updated — Users: {userCount}, Keys: {keyCount}, Ready: {IsEncryptionReady}");
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

                    // Registers the public key if not already known
                    if (!KnownPublicKeys.ContainsKey(user.UID))
                    {
                        KnownPublicKeys[user.UID] = publicKey;
                        Console.WriteLine($"[DEBUG] Public key registered for {username} — UID: {uid}");
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

                    // Posts a localized system message to the chat
                    Messages.Add("# - " + user.Username + " " + LocalizationManager.GetString("HasDisconnected") + ". #");

                    // Re-evaluates encryption state only if encryption is enabled
                    if (IsEncryptionEnabled)
                    {
                        UpdateEncryptionStatus();
                    }

                    Console.WriteLine($"[DEBUG] User disconnected — Username: {user.Username}, UID: {uid}");
                });
            }
        }
    }
}
