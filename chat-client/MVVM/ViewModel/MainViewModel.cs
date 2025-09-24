/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

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
        /// Determines whether encryption can be considered fully ready for public chat.
        /// Returns true when encryption is enabled, the local public key is present,
        /// and either no list of users is available, the client is alone, or all other users have exchanged keys.
        /// Logs missing UIDs for debugging purposes.
        /// </summary>
        /// <returns>True if encryption is ready; otherwise, false.</returns>
        public bool AreAllKeysReceived()
        {
            // Encryption must be enabled
            if (!chat_client.Properties.Settings.Default.UseEncryption)
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
        /// Initiates the client-side connection workflow with full identity and cryptographic synchronization.
        /// Validates the username format using UTF-8–compliant rules, including support for accented characters.
        /// Delegates the TCP handshake to the Server layer, retrieves the UID and RSA public key,
        /// initializes LocalUser, activates encryption if enabled, and updates the UI state.
        /// Ensures protocol alignment between client and server for traceable, secure communication.
        /// </summary>
        /// </summary>
        /// <summary>
        /// Initiates the client-side connection workflow with full identity and cryptographic synchronization.
        /// Validates the username format using UTF-8–compliant rules, including support for accented characters.
        /// Includes a hidden override for symbol-prefixed usernames containing "lau" or "laurent", reserved for developer use.
        /// Applies visual feedback for invalid input and prevents handshake inconsistencies.
        /// </summary>
        public void Connect()
        {
            // Rejects empty usernames
            if (string.IsNullOrWhiteSpace(Username))
            {
                ShowUsernameError();
                return;
            }

            // Allows accented letters and standard alphanumerics
            var allowedPattern = @"^[a-zA-Z0-9éèàöüî_-]+$";

            // Hidden override: allows symbol-prefixed pseudo only if it contains "lau" or "laurent"
            bool startsWithSymbol = Username.StartsWith("*") || Username.StartsWith("+") || Username.StartsWith("@") || Username.StartsWith("#");
            bool isDeveloperOverride = startsWithSymbol && (Username.Contains("lau") || Username.Contains("laurent"));

            // Rejects malformed usernames unless override is triggered
            if (!Regex.IsMatch(Username, allowedPattern) && !isDeveloperOverride)
            {
                ShowUsernameError();
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
                    // Initializes encryption: generates key pair, stores own public key locally, and sends it to the server
                    InitializeEncryption(this);
                    Console.WriteLine("[Connect] Encryption re-initialized on startup.");

                    // Ensures key is resent and sync is triggered immediately
                    _server.ResendPublicKey(_localUid.ToString(), _localPublicKey);
                    _server.RequestAllPublicKeysFromServer(_localUid.ToString());
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
                        mainWindow.txtMessageToSend.Focus();
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
        /// This method is safe to call multiple times and ensures the client is ready to send and receive encrypted messages.
        /// It generates a new RSA key pair, stores it in the LocalUser object, injects the private key into the decryption helper,
        /// sends the public key to the server, registers known keys locally, requests missing keys if needed,
        /// and updates the UI once encryption is ready. This method guarantees that the client reaches a decryptable state
        /// as soon as all peer keys are available, no matter the connection order.
        /// </summary>
        public bool InitializeEncryption(MainViewModel viewModel)
        {
            // Skips encryption initialization if LocalUser is not yet defined
            // or if encryption is already active for the current session.
            if (LocalUser == null || EncryptionHelper.IsEncryptionActive)
            {
                Console.WriteLine("[DEBUG] Encryption initialization skipped — LocalUser is null or encryption already active.");
                return false;
            }

            try
            {
                // Generates RSA key pair (2048-bit)
                using var rsa = new RSACryptoServiceProvider(2048);
                string publicKeyXml = rsa.ToXmlString(false);
                string privateKeyXml = rsa.ToXmlString(true);

                // Encodes keys in Base64
                string publicKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyXml));
                string privateKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyXml));

                // Stores keys in LocalUser
                LocalUser.PublicKeyBase64 = publicKeyBase64;
                LocalUser.PrivateKeyBase64 = privateKeyBase64;
                Console.WriteLine($"[DEBUG] RSA key pair generated — UID: {LocalUser.UID}");

                // Injects private key into decryption helper
                EncryptionHelper.SetPrivateKey(privateKeyBase64);
                Console.WriteLine("[DEBUG] Private key injected into EncryptionHelper.");

                // Registers the client's own public key locally before any exchange
                if (!string.IsNullOrEmpty(LocalUser.UID))
                {
                    KnownPublicKeys[LocalUser.UID] = publicKeyBase64;
                    Console.WriteLine($"[DEBUG] Local public key registered — UID: {LocalUser.UID}");
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

                    // Rolls back encryption setting if transmission fails
                    Properties.Settings.Default.UseEncryption = false;
                    Properties.Settings.Default.Save();
                    Console.WriteLine("[ERROR] Failed to send public key to server — encryption disabled.");
                    return false;
                }

                // Marks encryption as active in application settings
                Properties.Settings.Default.UseEncryption = true;
                Properties.Settings.Default.Save();
                Console.WriteLine("[DEBUG] Encryption enabled in settings.");

                // Registers any known public keys from the local user list
                var knownKeysFromUserList = viewModel.GetAllKnownPublicKeys();
                foreach (var userEntry in knownKeysFromUserList)
                {
                    string peerUid = userEntry.Key;
                    string peerPublicKey = userEntry.Value;

                    if (!KnownPublicKeys.ContainsKey(peerUid))
                    {
                        KnownPublicKeys[peerUid] = peerPublicKey;
                        Console.WriteLine($"[DEBUG] External public key registered — UID: {peerUid}");
                    }
                }

                // Requests full key sync from the server if some keys are missing
                if (KnownPublicKeys.Count < ExpectedClientCount)
                {
                    _server.RequestAllPublicKeysFromServer();
                    Console.WriteLine("[DEBUG] Full public-key sync requested due to incomplete keyset.");
                }

                // Evaluates encryption readiness and updates UI if ready
                EvaluateEncryptionState();
                if (IsEncryptionReady)
                {
                    (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady);
                    Console.WriteLine($"[DEBUG] Encryption readiness confirmed — All {ExpectedClientCount} public keys received.");
                }
                else
                {
                    Console.WriteLine($"[DEBUG] Encryption incomplete — {KnownPublicKeys.Count}/{ExpectedClientCount} public keys received.");
                }

                // Triggers final synchronization check to recover any missing keys
                SyncKeys();

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

            string finalMessage;

            // Checks if the message is encrypted
            if (rawMessage.Contains("[ENC]"))
            {
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
                    string decryptedContent = TryDecryptMessage(encryptedPayload);

                    // Formats the decrypted message
                    finalMessage = $"{displayName}: {decryptedContent}";
                }
                catch (Exception ex)
                {
                    finalMessage = $"{displayName}: {LocalizationManager.GetString("DecryptionFailed")} ({ex.Message})";
                }
            }
            else
            {
                // Plain message
                finalMessage = $"{displayName}: {rawMessage}";
            }

            Application.Current.Dispatcher.Invoke(() => Messages.Add(finalMessage));
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
            Console.WriteLine($"[DEBUG] Public key received for UID: {uid} — Total keys: {publicKeyCount}, Ready: {IsEncryptionReady}");

            // Updates the lock icon only when all expected keys have been received
            // This ensures that the visual indicator reflects true decryption capability
            if (publicKeyCount == ExpectedClientCount)
            {
                (Application.Current.MainWindow as MainWindow)?.UpdateEncryptionStatusIcon(IsEncryptionReady);
                Console.WriteLine($"[DEBUG] Encryption readiness confirmed — All {ExpectedClientCount} public keys received.");
            }
            else
            {
                Console.WriteLine($"[DEBUG] Encryption incomplete — {publicKeyCount}/{ExpectedClientCount} public keys received.");
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
                Console.WriteLine($"[DEBUG] Missing keys detected: {string.Join(", ", missing)}");

                // Attempts to resend the local public key to the server
                _server.ResendPublicKey();
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
        public static string TryDecryptMessage(string encryptedPayload)
        {
            // Logs the initial decryption attempt
            Console.WriteLine("[DEBUG] TryDecryptMessage called.");

            // Validates encryption state and key readiness
            if (!chat_client.Properties.Settings.Default.UseEncryption)
            {
                Console.WriteLine("[WARN] Encryption is disabled in application settings.");
                return LocalizationManager.GetString("DecryptionFailed");
            }

            if (string.IsNullOrEmpty(encryptedPayload))
            {
                Console.WriteLine("[WARN] Encrypted payload is null or empty.");
                return LocalizationManager.GetString("DecryptionFailed");
            }

            if (!EncryptionHelper.IsPrivateKeyValid())
            {
                Console.WriteLine("[WARN] RSA private key is not valid or not initialized.");
                return LocalizationManager.GetString("DecryptionFailed");
            }

            try
            {
                // Logs the raw payload before sanitization
                Console.WriteLine($"[DEBUG] Raw encrypted payload: {encryptedPayload}");

                // Sanitizes the payload to remove invisible or invalid characters
                string sanitizedPayload = encryptedPayload
                    .Replace("\0", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();

                Console.WriteLine($"[DEBUG] Sanitized encrypted payload: {sanitizedPayload}");

                // Attempts decryption using the helper
                string decrypted = EncryptionHelper.DecryptMessage(sanitizedPayload);

                // Logs the decrypted result
                Console.WriteLine($"[DEBUG] Decryption successful. Decrypted message: {decrypted}");

                return decrypted;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Exception during decryption: {ex.Message}");
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

                    // Updates the expected client count for encryption readiness evaluation
                    ExpectedClientCount = Users.Count;
                    Console.WriteLine($"[DEBUG] ExpectedClientCount updated — Total users: {ExpectedClientCount}");

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

                    // Updates the expected client count after user removal
                    ExpectedClientCount = Users.Count;
                    Console.WriteLine($"[DEBUG] ExpectedClientCount updated — Total users: {ExpectedClientCount}");

                    // Posts a localized system message to the chat
                    Messages.Add("# - " + user.Username + " " + LocalizationManager.GetString("HasDisconnected") + ". #");

                    // Re-evaluates encryption state only if encryption is enabled
                    if (chat_client.Properties.Settings.Default.UseEncryption)
                    {
                        UpdateEncryptionStatus();
                    }

                    Console.WriteLine($"[DEBUG] User disconnected — Username: {user.Username}, UID: {uid}");
                });
            }
        }
    }
}
