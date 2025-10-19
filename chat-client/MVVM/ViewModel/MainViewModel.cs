/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 19th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.Net;
using chat_client.Properties;
using Hardcodet.Wpf.TaskbarNotification;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;

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

        private static readonly Dictionary<string, string> dictionary = new();

        /// <summary>
        /// Stores public keys of other connected users, indexed by their UID.
        /// Used for encrypting messages to specific recipients.
        /// </summary>
        public Dictionary<string, string> KnownPublicKeys { get; } = dictionary;

        /// <summary>
        /// Connects or disconnects the client depending on the current connection state.
        /// Used by the main button and keyboard shortcuts.
        /// </summary>
        public RelayCommand ConnectDisconnectCommand { get; }

        /// <summary>
        /// Declaring the list as public ensures it can be resolved by WPF's binding system,
        // assuming the containing object is set as the DataContext.
        /// </summary>
        public List<string> EmojiList { get; } = new()
        {
            "😀", "👍", "🙏", "😅", "😂", "🤣", "😉", "😎", "😤", "😏", "🙈", "👋", "💪",
            "👌", "📌", "📞", "🔍", "⚠️", "✓", "🤝", "📣", "🚀", "☕", "🍺", "🍻", "🎉",
            "🍾", "🥳", "🍰", "🍱", "😁", "😇", "🤨", "🤷", "🤐", "😘", "❤️", "😲", "😬",
            "😷", "😴", "💤", "🔧", "🚗", "🏡", "☀️",  "🔥", "⭐", "🌟", "✨", "🌧️", "🕒"
        };


        /// <summary>
        /// Represents the number of clients expected to be connected for encryption readiness.
        /// This value is updated dynamically based on the current user list.
        /// </summary>
        public int ExpectedClientCount { get; set; } = 1; // Starts at 1 (self)

        /// <summary>
        /// Checks whether the local user has already sent their public key to the specified UID.
        /// </summary>
        /// <param name="uid">Unique identifier of the remote user.</param>
        /// <returns>True if the key has already been sent; otherwise, false.</returns>
        public bool HasSentKeyTo(string uid) => _uidsKeySentTo.Contains(uid);


        // What the user types in the second textbox on top left of
        // the MainWindow in View gets stored in this property (bound in XAML).
        public static string IPAddressOfServer { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the client’s connection state.
        /// Raises PropertyChanged for all UI elements that depend on connection status,
        /// and triggers the encryption pipeline when connecting with encryption enabled.
        /// </summary>
        public bool IsConnected
        {
            get => _isConnected;
            private set
            {
                if (_isConnected == value)
                    return;

                _isConnected = value;

                // Notifies that the connection state changed
                OnPropertyChanged();

                // Updates window title based on new connection state
                OnPropertyChanged(nameof(WindowTitle));

                // Refreshes the Connect/Disconnect button text
                OnPropertyChanged(nameof(ConnectButtonText));

                // Enables or disables credential inputs
                OnPropertyChanged(nameof(AreCredentialsEditable));

                // Shows or hides chat controls
                OnPropertyChanged(nameof(AreChatControlsVisible));

                // When opening a connection with encryption enabled, runs the pipeline
                if (_isConnected && UseEncryption)
                    ApplyEncryptionPipeline(enableEncryption: true);
            }
        }


        /// <summary>
        /// Gets or sets a value indicating whether the dark theme is active.
        /// Persists the choice to settings and applies the theme when changed.
        /// </summary>
        public bool IsDarkTheme
        {
            get => _isDarkTheme;
            set
            {
                if (_isDarkTheme == value) return;
                _isDarkTheme = value;
                OnPropertyChanged();

                // Saves the new theme preference
                Settings.Default.AppTheme = value ? "Dark" : "Light";
                Settings.Default.Save();

                // Applies the selected theme immediately
                ThemeManager.ApplyTheme(value);
            }
        }

        /// <summary>
        /// Gets a value indicating whether end-to-end encryption is fully ready.
        /// Encryption is ready when UseEncryption is on and either there are no other peers
        /// or all peer public keys have been received.
        /// </summary>
        public bool IsEncryptionReady
        {
            get => _isEncryptionReady;
            private set
            {
                // Exits if the state did not change
                if (_isEncryptionReady == value)
                    return;

                // Updates the encryption ready flag
                _isEncryptionReady = value;
                OnPropertyChanged(nameof(IsEncryptionReady));

                // Notifies that the icon source and visibility have changed
                OnPropertyChanged(nameof(IsEncryptionIconVisible));
            }
        }

        /// <summary>
        /// Gets a value indicating whether the encryption icon should be visible.
        /// Returns true when client is connected and encryption is enabled in settings.
        /// </summary>
        public bool IsEncryptionIconVisible
        {
            get => IsConnected && Settings.Default.UseEncryption;
        }

        /// <summary>
        /// Gets a value indicating whether a key‐exchange handshake is in progress.
        /// While true, the syncing icon is shown instead of the lock icon.
        /// </summary>
        public bool IsSyncingKeys
        {
            get => _isSyncingKeys;
            private set
            {
                // Exit if the state did not change
                if (_isSyncingKeys == value)
                    return;

                // Update the syncing flag
                _isSyncingKeys = value;
                OnPropertyChanged(nameof(IsSyncingKeys));
            }
        }

        /// <summary>
        /// Represents the currently authenticated user.
        /// Is initialized to an empty User instance to satisfy non-nullable requirements.
        /// </summary>
        public UserModel LocalUser { get; private set; } = new UserModel();

        /// <summary>
        /// Marks the specified UID as having received our public RSA key.
        /// Prevents duplicate transmissions during key exchange.
        /// </summary>
        /// <param name="uid">Unique identifier of the remote user.</param>
        public void MarkKeyAsSentTo(string uid) => _uidsKeySentTo.Add(uid);

        // What the user types in the textbox on bottom right
        // of the MainWindow in View gets stored in this property (bound in XAML).
        public static string Message { get; set; } = string.Empty;

        /// <summary>
        /// Represents a dynamic data collections that provides notification
        /// when a message is added or removed, or when the full list is refreshed.
        /// </summary>
        public ObservableCollection<string> Messages { get; set; }

        /// <summary>
        /// Event triggered when a property value changes, used to notify bound UI elements in data-binding scenarios.
        /// Implements the INotifyPropertyChanged interface to support reactive updates in WPF.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;

        public Server _server = new Server();

        /// <summary>
        /// Static UID used to identify system-originated messages such as server shutdown or administrative commands.
        /// This allows clients to verify message authenticity and prevent spoofed disconnects or control signals.
        /// </summary>
        public static readonly Guid SystemUID = Guid.Parse("00000000-0000-0000-0000-000000000001");

        /// <summary>
        /// Toggles the application theme based on the user's selection.
        /// Saves the preference, applies the theme with animation, and refreshes watermark visuals.
        /// </summary>
        public ICommand ThemeToggleCommand { get; }

        /// <summary>
        /// Gets or sets a value indicating whether encryption is enabled.
        /// Persists user choice and invokes the encryption pipeline when connected.
        /// </summary>
        public bool UseEncryption
        {
            get => _useEncryption;
            set
            {
                if (_useEncryption == value) return;
                _useEncryption = value;
                OnPropertyChanged(nameof(UseEncryption));

                // Persists the new setting
                Settings.Default.UseEncryption = value;
                Settings.Default.Save();

                // If already connected, performs the encryption pipeline
                if (IsConnected)
                    ApplyEncryptionPipeline(value);
            }
        }

        /// <summary>
        /// What the user types in the first textbox on top left of the MainWindow.
        /// Bound in XAML and triggers UI updates.
        /// </summary>
        public string Username
        {
            get => _username;
            set
            {
                if (_username == value) return;
                _username = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Represents a dynamic data collection that provides notification
        /// when a user is dded or removed, or when the full list is refreshed.
        /// </summary>
        public ObservableCollection<UserModel> Users { get; set; }

        /// <summary>
        /// Gets the localized window title according to connection state.
        /// </summary>
        public string WindowTitle =>
            "WPF chat client" + (IsConnected ? " – " + LocalizationManager.GetString("Connected") : "");
      
        // PROTECTED METHODS

        /// <summary>
        /// Notifies UI bindings that a property value has changed, enabling automatic interface updates.
        /// </summary>
        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        // PRIVATE FIELDS

        /// <summary>
        /// Tracks which users have already received our public RSA key.
        /// A HashSet is fast, especially for the Contains and Add operations.
        /// A UID can only be added once. This prevents redundant key transmissions.
        /// </summary>
        private readonly HashSet<string> _uidsKeySentTo = new();

        /// <summary>
        /// Stores the current theme selection state.
        /// Initialized from the saved AppTheme ("Dark" = true, otherwise false).
        /// </summary>
        private bool _isDarkTheme = Settings.Default.AppTheme == "Dark";

        /// <summary>
        /// Holds the current encryption ready state
        /// </summary>
        private bool _isEncryptionReady;

        /// <summary>
        /// Tracks whether we’ve seen the initial roster
        /// </summary>
        private bool _isFirstRosterUpdate = true;

        /// <summary>
        /// Holds the current key synchronization state
        /// </summary>
        private bool _isSyncingKeys;

        /// <summary>
        /// Backs the IsConnected property.
        /// </summary>
        private bool _isConnected;

        /// <summary>
        /// Indicates whether the next roster snapshot is the very first update
        /// received after connecting. Suppresses join/leave notifications on first load.
        /// </summary>
        private bool _isFirstRosterSnapshot = true;

        /// <summary>
        /// Holds the previous roster’s user IDs and usernames for diffing.
        /// </summary>
        private List<(Guid UserId, string Username)> _previousRosterSnapshot
            = new List<(Guid, string)>();

        /// <summary>
        /// Backs the UseEncryption property and is initialized from persisted settings.
        /// </summary>
        private bool _useEncryption = Settings.Default.UseEncryption;

        /// <summary>
        /// Holds what the user types in the first textbox on top left of the MainWindow
        private string _username = string.Empty;

        /// <summary>
        /// Initializes the MainViewModel instance.
        /// Sets up user and message collections, creates the server client,
        /// wires server events to handlers, and configures the Connect/Disconnect command.
        /// </summary>
        public MainViewModel()
        {
            // Initializes the collection of connected users
            Users = new ObservableCollection<UserModel>();

            // Initializes the collection of chat messages
            Messages = new ObservableCollection<string>();

            // Instantiates the server client and subscribes to its events
            _server = new Server();
            _server.UserConnectedEvent += OnUserConnected;
            _server.PlainMessageReceivedEvent += OnPlainMessageReceived;
            _server.EncryptedMessageReceivedEvent += OnEncryptedMessageReceived;
            _server.PublicKeyReceivedEvent += OnPublicKeyReceived;
            _server.UserDisconnectedEvent += OnUserDisconnected;
            _server.DisconnectedByServerEvent += OnDisconnectedByServer;

            // Subscribe to AppLanguage changes to refresh ConnectButtonText when the language setting updates
            Properties.Settings.Default.PropertyChanged += OnSettingsPropertyChanged;

            // Creates the Connect/Disconnect command and binds its Execute and CanExecute logic
            ConnectDisconnectCommand = new RelayCommand(
                () => ConnectDisconnect(),
                () => true
            );

            // Creates the ThemeToggleCommand used by the ToggleButton in the UI.
            // This command receives the toggle state (true for dark, false for light) as a parameter.
            ThemeToggleCommand = new RelayCommands<object>(param =>
            {
                // Converts the command parameter to a boolean and stores whether the dark theme is selected
                // (true) or not (false).
                bool isDarkThemeSelected = param is bool toggleState && toggleState;

                // Saves the theme preference
                Settings.Default.AppTheme = isDarkThemeSelected ? "Dark" : "Light";
                Settings.Default.Save();

                // Applies the theme with fade animation
                ThemeManager.ApplyTheme(isDarkThemeSelected);
            });


            // Registers to reevaluate the Connect/Disconnect command when connection state changes
            PropertyChanged += (sender, args) =>
            {
                if (args.PropertyName == nameof(IsConnected))
                    ConnectDisconnectCommand.RaiseCanExecuteChanged();
            };
        }

        /// <summary>
        /// Performs the encryption pipeline:
        /// clears old key material,
        /// initializes or tears down encryption,
        /// rolls back on failure,
        /// and logs the result.
        /// </summary>
        private void ApplyEncryptionPipeline(bool enableEncryption)
        {
            // Clears existing key material
            KnownPublicKeys.Clear();
            LocalUser.PublicKeyBase64 = string.Empty;
            LocalUser.PrivateKeyBase64 = string.Empty;
            EncryptionHelper.ClearPrivateKey();

            if (enableEncryption)
            {
                // Attempts to initialize encryption
                bool initSucceeded = InitializeEncryption();
                if (!initSucceeded)
                {
                    ClientLogger.Log("Encryption init failed – rolling back.", ClientLogLevel.Error);
                    UseEncryption = false;
                }
                else
                {
                    ClientLogger.Log("Encryption enabled successfully.", ClientLogLevel.Info);
                }
            }
            else
            {
                // Disables encryption path
                EvaluateEncryptionState();
                ClientLogger.Log("Encryption disabled successfully.", ClientLogLevel.Info);
            }
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
            ClientLogger.Log($"EvaluateEncryptionState: UseEncryption={Settings.Default.UseEncryption}, LocalUserReady={LocalUser != null}",
                ClientLogLevel.Debug);

            // Skips if encryption is disabled or if the local user is not initialized
            if (!Settings.Default.UseEncryption || LocalUser == null)
            {
                ClientLogger.Log("Skipping encryption readiness check — encryption disabled or local user not initialized.",
                    ClientLogLevel.Info);
                return false;
            }

            // Checks presence of the local public key
            bool hasLocalKey = !string.IsNullOrEmpty(LocalUser.PublicKeyBase64);
            ClientLogger.Log($"Local public key present: {hasLocalKey}", ClientLogLevel.Debug);

            if (!hasLocalKey)
            {
                ClientLogger.Log("Skipping encryption readiness check — local public key not yet generated.", ClientLogLevel.Info);
                return false;
            }

            // Handles solo mode where no other peers are connected
            if (Users.Count <= 1)        // Treats local user alone as ready
            {
                ClientLogger.Log("Solo mode detected — only local user; encryption considered ready.",
                    ClientLogLevel.Debug);

                ClientLogger.Log("Encryption is fully activated and ready (solo mode).",
                    ClientLogLevel.Info);
                return true;
            }

            List<string> missingKeys;

            // Locks the shared dictionary while computing missing entries
            lock (KnownPublicKeys)
            {
                var peerUids = Users.Select(u => u.UID).ToList();
                ClientLogger.Log($"Peer UIDs to verify: {string.Join(", ", peerUids)}",
                    ClientLogLevel.Debug);

                missingKeys = peerUids
                    .Except(KnownPublicKeys.Keys)
                    .ToList();

                ClientLogger.Log($"Number of missing keys detected: {missingKeys.Count}",
                    ClientLogLevel.Debug);
            }

            // Logs and aborts if any peer keys are missing
            if (missingKeys.Count > 0)
            {
                ClientLogger.Log($"Encryption not ready — missing keys for: {string.Join(", ", missingKeys)}",
                    ClientLogLevel.Debug);
                return false;
            }

            // All checks passed: logs activation and returns readiness
            ClientLogger.Log("Encryption is fully activated and ready.",
                ClientLogLevel.Info);
            return true;
        }

        /// <summary>
        /// Gets whether the chat panels (SpnDown, SpnEmojiPanel) are visible.
        /// They’re visible only when connected.
        /// </summary>
        public bool AreChatControlsVisible => IsConnected;

        /// <summary>
        /// Gets whether the username/IP textboxes are editable.
        /// They’re editable only when not connected.
        /// </summary>
        public bool AreCredentialsEditable => !IsConnected;

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
            if (!Settings.Default.UseEncryption)
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
        /// Removes every entry from the UI’s connected-users list,
        /// preparing to rebuild the roster from scratch.
        /// </summary>
        public void ClearConnectedUsers()
        {
            Users.Clear();
        }

        /// <summary>
        /// Connects to the chat server : 
        /// - validates the username 
        /// - performs the TCP handshake to obtain the user GUID and server public key
        /// - initializes LocalUser 
        /// - marks the connection as established
        /// - publishes the local public key and requests peers’ keys 
        /// - initializes encryption and synchronizes missing keys
        /// - updates the UI connection state 
        /// - saves the last used IP address
        /// </summary>
        public void Connect()
        {
            // Validates the username and shows an error if it is invalid
            var allowedPattern = @"^[a-zA-Z0-9éèàöüî_-]+$";
            if (string.IsNullOrWhiteSpace(Username) || !Regex.IsMatch(Username, allowedPattern))
            {
                ShowUsernameError();
                return;
            }

            try
            {
                // Performs the TCP handshake and retrieves UID and server public key
                var result = _server.ConnectToServer(Username.Trim(), IPAddressOfServer);
                if (result.uid == Guid.Empty || string.IsNullOrEmpty(result.publicKeyBase64))
                    throw new Exception(LocalizationManager.GetString("ConnectionFailed"));

                // Initializes the LocalUser model with the server-provided identity
                LocalUser = new UserModel
                {
                    Username = Username.Trim(),
                    UID = result.uid.ToString(),
                    PublicKeyBase64 = result.publicKeyBase64
                };
                ClientLogger.Log($"LocalUser initialized — Username: {LocalUser.Username}, UID: {LocalUser.UID}",
                    ClientLogLevel.Debug);

                // Marks the client as connected for plain messaging
                IsConnected = _server.IsConnected;
                ClientLogger.Log("Client connected — plain messages allowed before handshake.",
                    ClientLogLevel.Debug);

                if (Settings.Default.UseEncryption)
                {
                    // Assigns the in-memory RSA public key for this session
                    LocalUser.PublicKeyBase64 = EncryptionHelper.PublicKeyBase64;
                    ClientLogger.Log("Assigns in-memory RSA public key for this session.", ClientLogLevel.Debug);

                    // Publishes the local public key to the server to initiate key exchange
                    _server.SendPublicKeyToServer(LocalUser.UID, LocalUser.PublicKeyBase64);
                    ClientLogger.Log("Publishes local public key to server.", ClientLogLevel.Debug);

                    // Requests all known public keys from the server
                    _server.SendRequestAllPublicKeysFromServer();

                    // Initializes the encryption context and logs the outcome
                    if (InitializeEncryption())
                        ClientLogger.Log("Initializes encryption context on startup.", ClientLogLevel.Info);
                    else
                        ClientLogger.Log("Fails to initialize encryption context on startup.", ClientLogLevel.Error);

                    // Synchronizes missing peer public keys
                    SyncKeys();
                }

                // Updates the UI to the connected state and focuses the message input
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow &&
                        mainWindow.DataContext is MainViewModel viewModel)
                    {
                        viewModel.IsConnected = true;
                        mainWindow.TxtMessageToSend.Focus();
                    }
                });

                // Saves the last used IP address for future sessions
                Settings.Default.LastIPAddressUsed = IPAddressOfServer;
                Settings.Default.Save();
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Fails to connect or handshake: {ex.Message}", ClientLogLevel.Error);

                // Handles connection failure by showing an error dialog and resetting the UI
                Application.Current.Dispatcher.Invoke(() =>
                {
                    MessageBox.Show(LocalizationManager.GetString("ServerUnreachable"),
                        LocalizationManager.GetString("Error"), MessageBoxButton.OK, MessageBoxImage.Error);
                    ReinitializeUI();

                    // Sets IsConnected to false, which:
                    // - Enables the username/IP inputs
                    // - Hides the chat panels
                    // - Updates the window title and button text
                    IsConnected = false;
                });
            }
        }

        /// <summary>
        /// Gets the localized text for the connect/disconnect button.
        /// </summary>
        public string ConnectButtonText => 
            LocalizationManager.GetString(IsConnected ? "Disconnect" : "Connect");

        /// <summary>
        /// Connects or disconnects the client, depending on the server state.
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
        /// • Sends a framed DisconnectNotify packet if still connected  
        /// • Closes the underlying TCP connection via the server wrapper  
        /// • Clears all user and message data from the UI  
        /// • Updates the connection state to false, re-enabling login controls and hiding chat panels  
        /// </summary>
        public void Disconnect()
        {
            try
            {
                // Sends a clean-disconnect notification if the client is still connected
                if (_server?.IsConnected == true)
                {
                    _server.SendDisconnectNotifyToServer();
                    // Closes the connection to the server and underlying socket
                    _server.DisconnectFromServer();
                }

                // Clears all user and message data in the view
                ReinitializeUI();

                // Updates the connection state to false, re-enabling login controls
                IsConnected = false;
            }
            catch (Exception ex)
            {
                // Displays an error dialog if the disconnection process fails
                MessageBox.Show(
                    LocalizationManager.GetString("ErrorWhileDisconnecting") + ex.Message,
                    LocalizationManager.GetString("Error"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
        }

        /// <summary>
        /// Applies a full roster snapshot from the server, updates the Users list,
        /// and emits “X has joined” or “Y has left” messages only on subsequent updates.
        /// </summary>
        /// <param name="rosterEntries">
        /// The complete list of connected users as tuples of (UserId, Username, PublicKeyBase64).
        /// </param>
        public void DisplayRosterSnapshot(
            IEnumerable<(Guid UserId, string Username, string PublicKeyBase64)> rosterEntries)
        {
            // Materializes incoming roster for multiple passes
            var incomingSnapshot = rosterEntries
                .Select(e => (e.UserId, e.Username))
                .ToList();

            // On first snapshot, populates Users silently
            if (_isFirstRosterSnapshot)
            {
                Users.Clear();
                foreach (var (userId, username) in incomingSnapshot)
                {
                    Users.Add(new UserModel
                    {
                        UID = userId.ToString(),
                        Username = username,
                        PublicKeyBase64 = rosterEntries
                        .First(e => e.UserId == userId).PublicKeyBase64
                    });
                }

                // Records this state and disables silent mode
                _previousRosterSnapshot = incomingSnapshot;
                _isFirstRosterSnapshot = false;
                return;
            }

            // Determines who joined (users in incoming but not in previous)
            var joinedUsers = incomingSnapshot
                .Except(_previousRosterSnapshot)
                .ToList();

            // Determines who left (users in previous but not in incoming)
            var leftUsers = _previousRosterSnapshot
                .Except(incomingSnapshot)
                .ToList();
 
            /// <summary>
            /// Deconstructs each tuple in joinedUsers into two variables,
            /// ignores the first element (UserId) using the discard `_`,
            /// and captures only the username for the notification.
            /// </summary>
            foreach (var (_, username) in joinedUsers)
            {
                Messages.Add($"# {username} {LocalizationManager.GetString("HasConnected")} #");
            }

            /// <summary>
            /// Deconstructs each tuple in leftUsers into two variables,
            /// ignores the first element (UserId) using the discard `_`,
            /// and captures only the username for the notification.
            /// </summary>
            foreach (var (_, username) in leftUsers)
            {
                Messages.Add($"# {username} {LocalizationManager.GetString("HasDisconnected")} #");
            }

            // Refreshes the Users collection with the full, current roster
            Users.Clear();

            /// <summary>
            /// The foreach loop uses C# tuple deconstruction: each item in rosterEntries
            /// is a (Guid UserId, string Username, string PublicKeyBase64) tuple.
            /// By writing “var (userId, username, publicKey)” we unpack those three values
            /// directly into named variables, instead of accessing Item1/Item2/Item3.
            ///</summary>
            foreach (var (userId, username, publicKey) in rosterEntries)
            {
                Users.Add(new UserModel 
                {
                    UID = userId.ToString(),
                    Username = username,
                    PublicKeyBase64 = publicKey
                });
            }

            // Saves for next diff
            _previousRosterSnapshot = incomingSnapshot;
        }

        /// <summary>
        /// Determines whether encryption is ready and logs the result.
        /// </summary>
        /// <returns>True if encryption is enabled and all peer public keys are received; otherwise false.</returns>
        public bool EvaluateEncryptionState()
        {
            bool ready = Settings.Default.UseEncryption && AreAllKeysReceived();
            ClientLogger.Log($"EvaluateEncryptionState called — Ready: {ready}", ClientLogLevel.Debug);
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
        /// Returns the current custom port number stored in application settings.
        /// </summary>
        public static int GetCustomPort()
        {
            return Settings.Default.CustomPortNumber;
        }

        /// <summary>
        /// Gets the localized text for the connect/disconnect button.
        /// </summary>
        public string GetConnectButtonText =>
            LocalizationManager.GetString(IsConnected ? "Disconnect" : "Connect");

        /// <summary>
        /// Executes the complete encryption setup:
        ///   • Skips if no LocalUser is set or encryption is already active.
        ///   • Sets the syncing flag to true so the UI shows the grey syncing icon.
        ///   • Clears all stale peer public key data.
        ///   • Clears local key material from memory.
        ///   • Generates a new RSA key pair, registers it locally, and publishes the public key to the server.
        ///   • Enables encryption in application settings upon successful publish.
        ///   • Synchronizes peer public keys, requesting missing ones if necessary.
        ///   • Evaluates final encryption readiness and sets the ready flag.
        ///   • Persists handshake keys and the encryption flag to application settings.
        /// Wraps all steps in exception handling to maintain a safe state and ensure settings are always saved.
        /// </summary>
        /// <returns>True if encryption is successfully initialized and ready; false otherwise.</returns>
        public bool InitializeEncryption()
        {
            // Skips initialization if LocalUser is not defined or encryption is already active
            if (LocalUser == null || EncryptionHelper.IsEncryptionActive)
            {
                ClientLogger.Log("Skips encryption initialization — LocalUser is null or encryption already active.",
                    ClientLogLevel.Debug);
                return false;
            }

            // Shows the grey syncing icon during the entire setup process
            IsSyncingKeys = true;

            try
            {
                // Clears any previous peer public key data
                KnownPublicKeys.Clear();

                // Clears local key material from memory
                LocalUser.PublicKeyBase64 = string.Empty;
                LocalUser.PrivateKeyBase64 = string.Empty;
                EncryptionHelper.ClearPrivateKey();
                ClientLogger.Log("Cleared all previous key state.", ClientLogLevel.Debug);

                // Generates a new RSA key pair
                using var rsa = new RSACryptoServiceProvider(2048);
                string publicKeyXml = rsa.ToXmlString(false);
                string privateKeyXml = rsa.ToXmlString(true);
                string publicKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKeyXml));
                string privateKeyBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(privateKeyXml));

                LocalUser.PublicKeyBase64 = publicKeyBase64;
                LocalUser.PrivateKeyBase64 = privateKeyBase64;
                ClientLogger.Log($"Generated RSA key pair for UID {LocalUser.UID}.", ClientLogLevel.Debug);

                // Registers the new public key in the known-keys collection
                lock (KnownPublicKeys)
                {
                    KnownPublicKeys[LocalUser.UID] = publicKeyBase64;
                    ClientLogger.Log($"Registered local public key for UID {LocalUser.UID}.", 
                        ClientLogLevel.Debug);
                }

                // Sends the public key to the server
                bool keySentToServer = _server.SendPublicKeyToServer(LocalUser.UID, publicKeyBase64);
                if (!keySentToServer)
                {
                    ClientLogger.Log("Fails to send public key to server — aborts encryption setup.",
                        ClientLogLevel.Error);

                    MessageBox.Show(LocalizationManager.GetString("SendingClientsPublicRSAKeyToTheServerFailed"),
                        LocalizationManager.GetString("Error"),
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);

                    Settings.Default.UseEncryption = false;
                    return false;
                }

                // Enables encryption in application settings
                Settings.Default.UseEncryption = true;
                ClientLogger.Log("Enables encryption in application settings.",
                    ClientLogLevel.Info);

                // Synchronizes peer public keys; abort if that fails
                if (!SyncKeys())
                {
                    ClientLogger.Log("Peer key synchronization failed — aborts encryption setup.",
                        ClientLogLevel.Error);
                    return false;
                }

                // Evaluates final encryption readiness and sets the ready flag
                IsEncryptionReady = EvaluateEncryptionState();
                
                if (IsEncryptionReady)
                {
                    ClientLogger.Log("Encryption ready — coloured lock icon displayed.", ClientLogLevel.Info);
                }

                return IsEncryptionReady;
            }
            catch (Exception ex)
            {
                // On any error, disables encryption to maintain a safe state
                Settings.Default.UseEncryption = false;
                ClientLogger.Log($"Exception during encryption initialization: {ex.Message}",  ClientLogLevel.Error);
                return false;
            }
            finally
            {
                // Persists handshake keys and encryption flag to settings
                Settings.Default.HandshakePublicKey = LocalUser?.PublicKeyBase64;
                Settings.Default.HandshakePrivateKey = LocalUser?.PrivateKeyBase64;
                Settings.Default.Save();
                ClientLogger.Log("Persists handshake keys and encryption flag.", ClientLogLevel.Debug);

                // Clears the syncing flag only if the icon will switch off grey
                if (IsEncryptionReady || !Settings.Default.UseEncryption)
                {
                    IsSyncingKeys = false;
                }
            }
        }

        /// <summary>
        /// Handles a server-initiated disconnect command (opcode: DisconnectClient).  
        /// • Closes the client connection gracefully.  
        /// • Clears the user list.  
        /// • Posts a localized system message indicating server disconnection.  
        /// • Raises PropertyChanged for IsConnected to refresh the UI state.  
        /// </summary>
        public void OnDisconnectedByServer()
        {
            // Attempts to close the connection
            try
            {
                _server.DisconnectFromServer();
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Error during server-initiated disconnect: {ex.Message}",
                    ClientLogLevel.Error);
            }

            // Executes UI-bound updates on the dispatcher thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                // Clears all users
                Users.Clear();

                // Posts a system notice to the chat history
                Messages.Add($"# {LocalizationManager.GetString("ServerDisconnected")} #");

                // Notifies the UI that the connection status changed
                OnPropertyChanged(nameof(IsConnected));
            });
        }


        /// <summary>
        /// Handles an incoming encrypted message.
        /// Converts the cipher bytes to Base64, attempts decryption,
        /// resolves the sender’s display name, and marshals the result
        /// onto the UI thread for display.
        /// </summary>
        /// <param name="senderUid">UID of the user who sent the message.</param>
        /// <param name="cipherBytes">Encrypted payload as a byte array.</param>
        private void OnEncryptedMessageReceived(Guid senderUid, byte[] cipherBytes)
        {
            // Converts the raw cipher bytes to Base64 for the decryption helper
            string base64 = Convert.ToBase64String(cipherBytes);

            // Attempts to decrypt; fall back to a localized error message on failure
            string plaintext;
            try
            {
                plaintext = EncryptionHelper.DecryptMessage(base64);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Decryption error from {senderUid}: {ex.Message}", ClientLogLevel.Error);
                plaintext = LocalizationManager.GetString("DecryptionFailed");
            }

            // Looks up the sender’s username in the Users collection; default to the GUID string
            string username = Users?
                .FirstOrDefault(u => string.Equals(u.UID, senderUid.ToString(), StringComparison.OrdinalIgnoreCase))
                ?.Username
                ?? senderUid.ToString();

            // Dispatches the formatted message to the UI thread for insertion into the chat log
            Application.Current.Dispatcher.Invoke(() =>
            {
                Messages.Add($"{username}: {plaintext}");
            });
        }

        /// <summary>
        /// Handles a delivered plain‐text message by prefixing the sender’s name.
        /// Marshals the update to the UI thread and appends "sender: message" to the chat.
        /// </summary>
        /// <param name="senderName">The display name of the message sender.</param>
        /// <param name="messageToDisplay">The content of the received message.</param>
        public void OnPlainMessageReceived(string senderName, string messageToDisplay)
        {
            try
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Messages.Add($"{senderName}: {messageToDisplay}");
                });
            }
            catch (Exception ex)
            {
                ClientLogger.Log(
                    $"PlainMessageReceived handler failed: {ex.Message}",
                    ClientLogLevel.Error
                );
            }
        }

        /// <summary>
        /// Handles a received public‐key event.
        /// Validates input, updates the KnownPublicKeys dictionary in a thread-safe manner,
        /// logs whether the key was added, updated, or duplicated,
        /// re-evaluates encryption readiness,
        /// and refreshes the UI lock icon if the client becomes ready.
        /// </summary>
        /// <param name="senderUid">The UID of the peer who provided the public key.</param>
        /// <param name="publicKeyBase64">The Base64-encoded RSA public key.</param>
        public void OnPublicKeyReceived(string senderUid, string publicKeyBase64)
        {
            // Discard if either UID or key is missing
            if (string.IsNullOrWhiteSpace(senderUid) || string.IsNullOrWhiteSpace(publicKeyBase64))
            {
                ClientLogger.Log("Discarded public key: missing UID or key.",
                    ClientLogLevel.Warn);
                return;
            }

            bool isNewOrUpdatedKey = false;

            // Protects the dictionary from concurrent writes
            lock (KnownPublicKeys)
            {
                if (KnownPublicKeys.TryGetValue(senderUid, out var existingKey))
                {
                    if (existingKey == publicKeyBase64)
                    {
                        ClientLogger.Log($"Duplicate public key for {senderUid}; no change.",
                            ClientLogLevel.Debug);
                    }
                    else
                    {
                        KnownPublicKeys[senderUid] = publicKeyBase64;
                        isNewOrUpdatedKey = true;
                        ClientLogger.Log($"Updated public key for {senderUid}.",
                            ClientLogLevel.Info);
                    }
                }
                else
                {
                    KnownPublicKeys.Add(senderUid, publicKeyBase64);
                    isNewOrUpdatedKey = true;
                    ClientLogger.Log($"Registered new public key for {senderUid}.",
                        ClientLogLevel.Info);
                }
            }

            // Re-evaluates overall encryption state
            EvaluateEncryptionState();

            // Refreshes the UI lock icon if this key makes encryption fully ready
            if (isNewOrUpdatedKey && IsEncryptionReady)
            {
                ClientLogger.Log($"Encryption readiness confirmed after registering key for {senderUid}.",
                    ClientLogLevel.Debug);
            }
        }

        /// Handles changes to the AppLanguage setting:
        /// - Switches the localization culture in LocalizationManager.
        /// - Raises PropertyChanged for all UI-bound properties that use localized strings,
        /// ensuring immediate refresh without window reload.
        /// </summary>
        private void OnSettingsPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName != nameof(Settings.Default.AppLanguage))
                return;

            // Changes the current culture used by LocalizationManager
            LocalizationManager.Initialize(Properties.Settings.Default.AppLanguage);

            // Forces WPF to re-query any localized properties
            OnPropertyChanged(nameof(ConnectButtonText));
            OnPropertyChanged(nameof(WindowTitle));
        }

        /// <summary>
        /// Handles a new user join event.
        /// Reads the provided UID, username, and public key.
        /// Adds the user to the Users collection if not already present.
        /// Registers the user’s public key and re-evaluates encryption state.
        /// Posts a system notice to the chat UI on the dispatcher thread.
        /// </summary>
        /// <param name="uid">The joining user’s unique identifier.</param>
        /// <param name="username">The joining user’s display name.</param>
        /// <param name="publicKey">The joining user’s RSA public key (base64).</param>
        public void OnUserConnected(string uid, string username, string publicKey)
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
                ClientLogger.Log($"ExpectedClientCount updated — Total users: {ExpectedClientCount}",
                    ClientLogLevel.Debug);

                // Registers the public key if not already known
                if (!KnownPublicKeys.ContainsKey(uid))
                {
                    KnownPublicKeys[uid] = publicKey;
                    ClientLogger.Log($"Public key registered for {username} — UID: {uid}",
                        ClientLogLevel.Debug);
                }

                // Re-evaluates whether encryption features can be enabled
                EvaluateEncryptionState();

                // Posts a system notice to the chat window
                Messages.Add($"# {username} {LocalizationManager.GetString("HasConnected")} #");
            });
        }

        /// <summary>
        /// Handles a user disconnect event (opcode: DisconnectNotify).
        /// Removes the specified user from the roster,
        /// posts a system notice to the chat,
        /// updates the expected client count,
        /// and rechecks encryption readiness if enabled.
        /// </summary>
        /// <param name="uid">UID of the user who disconnected.</param>
        /// <param name="username">Display name of the user who disconnected.</param>
        public void OnUserDisconnected(string uid, string username)
        {
            try
            {
                // Locates the user by UID
                var user = Users.FirstOrDefault(u => u.UID == uid);
                if (user == null)
                    return;

                // Removes the user from the UI-bound list
                Users.Remove(user);

                // Updates and logs the expected client count
                ExpectedClientCount = Users.Count;
                ClientLogger.Log($"ExpectedClientCount updated — Total users: {ExpectedClientCount}",
                    ClientLogLevel.Debug);

                // Rechecks encryption readiness when encryption is active
                if (Settings.Default.UseEncryption)
                    EvaluateEncryptionState();

                // Logs the disconnect event
                ClientLogger.Log($"User disconnected — Username: {username}, UID: {uid}",
                    ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"UserDisconnected handler failed: {ex.Message}", ClientLogLevel.Error);
            }
        }

        /// <summary>
        /// Represents the user's preference for minimizing the app to the system tray.
        /// When changed, it updates the application setting, saves it, and shows or hides the tray icon accordingly.
        /// This property is bound to the ReduceToTray toggle in the settings UI.
        /// </summary>
        public bool ReduceToTray
        {
            get => Settings.Default.ReduceToTray;
            set
            {
                if (Settings.Default.ReduceToTray != value)
                {
                    Settings.Default.ReduceToTray = value;
                    Settings.Default.Save();

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
        /// Raises PropertyChanged for all connection-related bindings.
        /// </summary>
        public void RefreshConnectionBindings()
        {
            // Forces WPF to re-read all properties
            OnPropertyChanged(nameof(IsConnected));
            OnPropertyChanged(nameof(WindowTitle));
            OnPropertyChanged(nameof(ConnectButtonText));
            OnPropertyChanged(nameof(AreCredentialsEditable));
            OnPropertyChanged(nameof(AreChatControlsVisible));
        }

        /// <summary>
        /// Clears all chat data and resets the ViewModel connection state,
        /// causing the UI to return to its initial (disconnected) layout via bindings.
        /// </summary>
        public void ReinitializeUI()
        {
            // Clears the collections bound to the user list and chat window
            Users.Clear();
            Messages.Clear();
        }

        /// <summary>
        /// Resets the first-update flag and clears the previous snapshot.
        /// Should be called on new connection or on full disconnect.
        /// </summary>
        public void ResetRosterState()
        {
            _isFirstRosterUpdate = true;
            _previousRosterSnapshot.Clear();
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
        /// Synchronizes the local public key with each connected peer.
        /// Shows the grey “syncing” icon, requests any missing peer key,
        /// then updates encryption readiness and hides the syncing icon.
        /// </summary>
        /// <returns>True if encryption is ready (all keys present or solo mode), false otherwise.</returns>
        public bool SyncKeys()
        {
            // Exits if encryption is disabled
            if (!Settings.Default.UseEncryption)
            {
                IsEncryptionReady = false;
                IsSyncingKeys = false;
                return false;
            }

            // Shows grey syncing icon
            IsSyncingKeys = true;

            // Snapshots a list of peer UIDs (exclude local)
            var lstPeerIds = Users
                .Where(u => u.UID != LocalUser.UID)
                .Select(u => u.UID)
                .ToList();

            // If solo mode is detected, marks ready immediately
            if (lstPeerIds.Count == 0)
            {
                IsEncryptionReady = true;
                IsSyncingKeys = false;
                return true;
            }

            // Identifies missing keys
            List<string> missingKeys;
            lock (KnownPublicKeys)
            {
                missingKeys = lstPeerIds.Where(uid => !KnownPublicKeys.ContainsKey(uid))
                    .ToList();
            }

            // Requests each missing peer key
            foreach (var uid in missingKeys)
                _server.SendRequestToPeerForPublicKey(Guid.Parse(uid));

            // Finalizes flags
            IsEncryptionReady = (missingKeys.Count == 0);
            IsSyncingKeys = !IsEncryptionReady;
            return IsEncryptionReady;
        }

        /// <summary>
        /// Enables or disables encryption, with full validation, key‐wipe,
        /// pipeline execution (init or teardown), rollback on failure, and logging.
        /// </summary>
        public void ToggleEncryption(bool enableEncryption)
        {
            // Remember the old setting in case we need to roll back
            bool settingPreviousValue = Settings.Default.UseEncryption;

            // Persists the new flag
            Settings.Default.UseEncryption = enableEncryption;
            Settings.Default.Save();

            // Validates prerequisites
            if (LocalUser == null || !IsConnected)
            {
                ClientLogger.Log("Encryption process failed – missing LocalUser or not connected.",
                    ClientLogLevel.Warn);

                // Roll back UI and settings
                Settings.Default.UseEncryption = settingPreviousValue;
                OnPropertyChanged(nameof(Settings.Default.UseEncryption));
                return;
            }

            // Clears old key material
            KnownPublicKeys.Clear();
            LocalUser.PublicKeyBase64 = string.Empty;
            LocalUser.PrivateKeyBase64 = string.Empty;
            EncryptionHelper.ClearPrivateKey();

            // Executes the pipeline: init or disable
            bool pipelineSucceeded = enableEncryption ? 
                InitializeEncryption()       // true if init succeeded
                : EvaluateEncryptionState();   // true if disable succeeded

            if (!pipelineSucceeded)
            {
                ClientLogger.Log($"Encryption pipeline {(enableEncryption ? "init" : "teardown")} failed – rolling back.",
                    ClientLogLevel.Error);

                // Restores previous setting
                Settings.Default.UseEncryption = settingPreviousValue;
                Settings.Default.Save();
                OnPropertyChanged(nameof(Settings.Default.UseEncryption));
            }
            else
            {
                ClientLogger.Log(enableEncryption ?
                    "Encryption enabled successfully."
                    : "Encryption disabled successfully.",
                    ClientLogLevel.Info);
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
            ClientLogger.Log("TryDecryptMessage called.", ClientLogLevel.Debug);

            if (!Settings.Default.UseEncryption)
            {
                ClientLogger.Log("Encryption is disabled in application settings.", ClientLogLevel.Warn);
                return LocalizationManager.GetString("DecryptionFailed");
            }

            if (string.IsNullOrWhiteSpace(encryptedPayload))
            {
                ClientLogger.Log("Encrypted payload is null or empty.", ClientLogLevel.Warn);
                return LocalizationManager.GetString("DecryptionFailed");
            }

            try
            {
                ClientLogger.Log($"Raw encrypted payload: {encryptedPayload}", ClientLogLevel.Debug);

                // Sanitizes payload: strips control chars and trims whitespace.
                string sanitized = encryptedPayload
                    .Replace("\0", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Trim();
                ClientLogger.Log($"Sanitized encrypted payload: {sanitized}", ClientLogLevel.Debug);

                // Delegates to EncryptionHelper for the actual decrypt.
                string result = EncryptionHelper.DecryptMessage(sanitized);
                ClientLogger.Log($"Decryption successful. Decrypted message: {result}", ClientLogLevel.Debug);

                return result;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Exception during decryption: {ex.Message}", ClientLogLevel.Error);
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
                Settings.Default.CustomPortNumber = chosenPort;
                Settings.Default.Save();
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
                    ClientLogger.Log($"User in list of users — UID: {user.UID}, HasKey: {hasKey}", ClientLogLevel.Debug);
                }
            }

            // Logs the readiness state before updating the icon
            ClientLogger.Log($"UpdateEncryptionStatusIcon called — isReady: {IsEncryptionReady}", ClientLogLevel.Debug);

            // Logs summary of list of users and key distribution
            int userCount = Users?.Count ?? 0;
            int keyCount = KnownPublicKeys?.Count ?? 0;
            ClientLogger.Log($"Encryption status updated — Users: {userCount}, Keys: {keyCount}, Ready: {IsEncryptionReady}", ClientLogLevel.Debug);
        }
    }
}
