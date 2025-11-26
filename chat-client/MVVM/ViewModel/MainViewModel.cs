/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 26th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.Net;
using chat_client.Properties;
using Hardcodet.Wpf.TaskbarNotification;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
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
        // PRIVATE FIELDS

        /// <summary>
        /// Tracks which users have already received our public RSA key.
        /// A HashSet is fast, especially for the Contains and Add operations.
        /// A UID can only be added once. This prevents redundant key transmissions.
        /// </summary>
        private readonly HashSet<Guid> _uidsKeySentTo = new();

        /// <summary>
        /// Atomic guard to ensure the client-side disconnect sequence runs only once.
        /// 0 = not running, 1 = already invoked.
        /// </summary>
        private int _clientDisconnecting = 0;

        // Cancellation source for the running encryption pipeline;
        // cancelled when connection or setting changes
        private CancellationTokenSource? _encryptionCts;

        /// <summary>
        /// Ensures that encryption initialization runs only once per session.
        /// Used as an interlocked flag: 0 = not initialized, 1 = already initialized.
        /// Reset to 0 during disconnect cleanup to allow fresh initialization.
        /// </summary>
        private int _encryptionInitOnce = 0;

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
        /// Provides access to the encryption pipeline instance,
        /// which manages key generation, publication, synchronization,
        /// and readiness evaluation for secure communication.
        /// </summary>
        private EncryptionPipeline _pipeline;

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

        // PUBLIC PROPERTIES

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
        public bool HasSentKeyTo(Guid uid) => _uidsKeySentTo.Contains(uid);


        // What the user types in the second textbox on top left of
        // the MainWindow in View gets stored in this property (bound in XAML).
        public static string IPAddressOfServer { get; set; } = string.Empty;

        /// <summary>
        /// Proxy to the ClientConnection state.
        /// Ensures the UI binds to the actual TCP connection status.
        /// </summary>
        public bool IsConnected => _clientConn?.IsConnected ?? false;

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

        /// <summary>Stores public keys of other connected users, indexed by their UID.</summary>
        /// <remarks>Used for encrypting messages to specific recipients; values are DER-encoded public key bytes.</remarks>
        public Dictionary<Guid, byte[]> KnownPublicKeys { get; } = new Dictionary<Guid, byte[]>();

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
        public void MarkKeyAsSentTo(Guid uid) => _uidsKeySentTo.Add(uid);

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

        public ClientConnection _clientConn;

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
        /// Proxy-property: gets or sets the application setting
        /// indicating whether encryption is enabled.
        /// </summary>
        public bool UseEncryption
        {
            get => Settings.Default.UseEncryption;
            set
            {
                if (Settings.Default.UseEncryption == value)
                    return;

                // Persists new preference immediately
                Settings.Default.UseEncryption = value;
                Settings.Default.Save();

                // Notifies UI bindings
                OnPropertyChanged(nameof(UseEncryption));
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

        /// <summary>
        /// Initializes the MainViewModel instance.
        /// Sets up user and message collections, creates the encryption pipeline and server client,
        /// wires server events to handlers, and configures UI commands.
        /// </summary>
        public MainViewModel()
        {
            // Initializes collections bound to the UI
            Users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<string>();

            // Instantiates the encryption pipeline and client connection
            _pipeline = new EncryptionPipeline(this, action => Application.Current.Dispatcher.Invoke(action));
            _clientConn = new ClientConnection(_pipeline, action => Application.Current.Dispatcher.Invoke(action));

            // Subscribes to client connection events
            _clientConn.UserConnectedEvent += OnUserConnected;
            _clientConn.PlainMessageReceivedEvent += OnPlainMessageReceived;
            _clientConn.EncryptedMessageReceivedEvent += OnEncryptedMessageReceived;
            _clientConn.PublicKeyReceivedEvent += OnPublicKeyReceived;
            _clientConn.UserDisconnectedEvent += OnUserDisconnected;
            _clientConn.DisconnectedByServerEvent += OnDisconnectedByServer;

            // Subscribes to language changes to refresh UI text dynamically
            Properties.Settings.Default.PropertyChanged += OnSettingsPropertyChanged;

            /// <summary>
            /// Creates the Connect/Disconnect RelayCommand.
            /// Always executable by design, and launches the asynchronous connect/disconnect
            /// logic without blocking the UI thread.
            /// </summary>
            /// <remarks>
            /// RelayCommand takes an Action, so we cannot directly pass a Task-returning method,
            /// but start the asynchronous call in a fire-and-forget manner. 
            /// The "_ =" is a convention to indicate that the returned
            /// Task is intentionally ignored. 
            /// CanExecute remains true, so the button is always clickable.
            /// </remarks>
            ConnectDisconnectCommand = new RelayCommand(
                () => { _ = ConnectDisconnectAsync(); }, 
                () => true
            );

            // Creates ThemeToggleCommand bound to the UI toggle button
            ThemeToggleCommand = new RelayCommands<object>(param =>
            {
                bool isDarkThemeSelected = false;

                // Checks if param is a boolean before using it
                if (param is bool toggleState)
                {
                    // Assigns the value of toggleState directly
                    isDarkThemeSelected = toggleState;
                }

                // Saves the theme preference
                Settings.Default.AppTheme = isDarkThemeSelected ? "Dark" : "Light";
                Settings.Default.Save();

                // Applies the theme with fade animation
                ThemeManager.ApplyTheme(isDarkThemeSelected);
            });

            // Reevaluates Connect/Disconnect command when connection state changes
            PropertyChanged += (sender, args) =>
            {
                if (args.PropertyName == nameof(IsConnected))
                {
                    ConnectDisconnectCommand.RaiseCanExecuteChanged();
                }
            };
        }

        /// <summary>
        /// Orchestrates UI-side connection workflow:
        /// • validates username
        /// • delegates handshake to clientConn
        /// • initializes LocalUser
        /// • updates UI state and focus
        /// • initializes encryption if enabled
        /// • persists last used IP
        /// </summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            /// <summary>
            /// Username rules:
            /// - first character must be a letter (ASCII or selected accented letters)
            /// - allowed subsequent characters: letters (ASCII + selected accents), digits,
            ///   underscore (_), hyphen (-) or a single normal space (U+0020)
            /// - no leading or trailing space, no consecutive spaces, no tabs or other Unicode space characters
            /// - at least one character required
            /// </summary>
            /// <remarks>
            /// - `^(?!.*  )` prevents two consecutive normal spaces anywhere in the string.
            /// - `(?!.* $)` prevents a trailing normal space at the end of the string.
            /// - The first-character class forces the username to start with a letter (ASCII or accented),
            ///   so names cannot begin with a digit, underscore, hyphen or space.
            /// - The subsequent-character class allows ASCII letters, digits and the selected accented letters
            ///   (both uppercase and lowercase), plus underscore and hyphen; a single normal space (U+0020)
            ///   is allowed between characters but not consecutively.
            /// - Tab characters and other Unicode whitespace characters are not permitted because they are
            ///   not included in the allowed character class; only the normal space U+0020 is accepted.
            /// </remarks>
            var allowedPattern = @"^(?!.*  )(?!.* $)[A-Za-zÀÁÂÄÃÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÖÕÙÚÛÜÝŸàáâäãåæçèéêëìíîïñòóôöõùúûüýÿ][A-Za-z0-9ÀÁÂÄÃÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÖÕÙÚÛÜÝŸàáâäãåæçèéêëìíîïñòóôöõùúûüýÿ _-]*(?: (?! ))*$";

            if (string.IsNullOrWhiteSpace(Username) || !Regex.IsMatch(Username, allowedPattern))
            {
                ShowUsernameError();
                return;
            }

            try
            {
                /// <summary> Delegates handshake to client connection and retrieves UID and server public key </summary>
                var (uid, publicKeyDer) = await _clientConn.ConnectToServerAsync(Username.Trim(), IPAddressOfServer, cancellationToken).ConfigureAwait(false);

                /// <summary> Guards against handshake failure (empty UID or key) </summary>
                if (uid == Guid.Empty || publicKeyDer == null || publicKeyDer.Length == 0)
                {
                    ClientLogger.LogLocalized("ConnectionFailed", ClientLogLevel.Error);
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        ReinitializeUI();
                        OnPropertyChanged(nameof(IsConnected));
                    });
                    return;
                }

                /// <summary> Initializes LocalUser with handshake results </summary>
                LocalUser = new UserModel { Username = Username.Trim(), UID = uid, PublicKeyDer = publicKeyDer };
                ClientLogger.Log($"LocalUser initialized — Username: {LocalUser.Username}, UID: {LocalUser.UID}", ClientLogLevel.Debug);

                /// <summary> Updates UI bindings to reflect connected state </summary>
                Application.Current.Dispatcher.Invoke(() =>
                {
                    OnPropertyChanged(nameof(IsConnected));
                    OnPropertyChanged(nameof(WindowTitle));
                    OnPropertyChanged(nameof(ConnectButtonText));
                    OnPropertyChanged(nameof(AreCredentialsEditable));
                    OnPropertyChanged(nameof(AreChatControlsVisible));
                });

                ClientLogger.Log("Client connected — plain messages allowed before handshake.", ClientLogLevel.Debug);

                /// <summary> Initializes encryption only if requested by settings </summary>
                if (Settings.Default.UseEncryption)
                {
                    try
                    {
                        /// <summary> Ensures pipeline exists before usage </summary> 
                        if (_pipeline == null)
                        {
                            _pipeline = new EncryptionPipeline(this, action => Application.Current.Dispatcher.Invoke(action));
                            ClientLogger.Log("EncryptionPipeline is created before usage.", ClientLogLevel.Debug);
                        }

                        /// <summary> Assigns in-memory RSA public key for this session </summary> 
                        LocalUser.PublicKeyDer = EncryptionHelper.PublicKeyDer;
                        ClientLogger.Log("Assigns in-memory RSA public key for this session.", ClientLogLevel.Debug);

                        /// <summary> Publishes local key to the server </summary>
                        await _clientConn.SendPublicKeyToServerAsync(LocalUser.UID, LocalUser.PublicKeyDer, cancellationToken).ConfigureAwait(false);
                        ClientLogger.Log("Publishes local public key to server.", ClientLogLevel.Debug);

                        /// <summary> Requests a snapshot of all known public keys </summary>
                        await _clientConn.SendRequestAllPublicKeysFromServerAsync(cancellationToken).ConfigureAwait(false);

                        /// <summary> Initializes local encryption context </summary>
                        if (await _pipeline.InitializeEncryptionAsync(cancellationToken).ConfigureAwait(false))
                            ClientLogger.Log("Initializes encryption context on startup.", ClientLogLevel.Info);
                        else
                            ClientLogger.Log("Fails to initialize encryption context on startup.", ClientLogLevel.Error);

                        /// <summary> Evaluates encryption readiness (solo or multi-client) </summary>
                        _pipeline.EvaluateEncryptionState();
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"Encryption setup failed: {ex.Message}", ClientLogLevel.Error);
                    }
                }

                /// <summary> Restores focus to message input for immediate typing </summary>
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                        mainWindow.TxtMessageToSend.Focus();
                });

                /// <summary> Saves last used IP address for next session </summary>
                Settings.Default.LastIPAddressUsed = IPAddressOfServer;
                Settings.Default.Save();
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("Connection attempt canceled by user.", ClientLogLevel.Info);

                /// <summary> Resets UI state after cancellation </summary>
                Application.Current.Dispatcher.Invoke(() =>
                {
                    ReinitializeUI();
                    OnPropertyChanged(nameof(IsConnected));
                });
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Fails to connect or handshake: {ex.Message}", ClientLogLevel.Error);

                /// <summary> Displays error and resets UI to disconnected state </summary>
                Application.Current.Dispatcher.Invoke(() =>
                {
                    MessageBox.Show(LocalizationManager.GetString("ServerUnreachable"),
                        LocalizationManager.GetString("Error"), MessageBoxButton.OK, MessageBoxImage.Error);

                    ReinitializeUI();
                    OnPropertyChanged(nameof(IsConnected));
                });
            }
        }

        /// <summary>
        /// Gets the localized text for the connect/disconnect button.
        /// </summary>
        public string ConnectButtonText => 
            LocalizationManager.GetString(IsConnected ? "Disconnect" : "Connect");

        /// <summary>
        /// Connects or disconnects the client depending on the current connection state.
        /// Uses an asynchronous pattern so the UI thread is not blocked while the network
        /// handshake runs. 
        /// The method resumes on the UI context after awaits so subsequent
        /// UI updates are safe.
        /// </summary>
        public async Task ConnectDisconnectAsync()
        {
            if (_clientConn.IsConnected)
            {
                Disconnect();
                return;
            }

            // If not connected, start the asynchronous connect/handshake sequence.
            // Awaiting ConnectAsync allows exceptions to propagate to the caller for handling.
            // ConfigureAwait(true) requests that the continuation runs back on the captured
            // synchronization context (the UI thread) so that any UI updates after the await
            // are safe to perform directly.
            await ConnectAsync().ConfigureAwait(true);
        }


        /// <summary>
        /// Sends a disconnect notify (if connected), closes the TCP connection via clientConn,
        /// clears UI state, notifies bindings, disables encryption, and resets init flags.
        /// </summary>
        public void Disconnect()
        {
            try
            {
                /// <summary> Sends a framed DisconnectNotify if the client is still connected </summary>
                if (_clientConn?.IsConnected == true)
                {
                    try
                    {
                        // Fire-and-forget disconnect notify
                        _ = _clientConn.SendDisconnectNotifyToServerAsync(CancellationToken.None);
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"SendDisconnectNotifyToServerAsync failed: {ex.Message}", ClientLogLevel.Error);
                    }

                    /// <summary> Fire-and-forget : loses the underlying TCP connection via the client connection </summary>
                    _ = _clientConn.DisconnectFromServerAsync();
                }

                /// <summary> Clears all user/message data in the view </summary>
                ReinitializeUI();

                /// <summary> Notifies UI bindings to reflect disconnected state </summary>
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(WindowTitle));
                OnPropertyChanged(nameof(ConnectButtonText));
                OnPropertyChanged(nameof(AreCredentialsEditable));
                OnPropertyChanged(nameof(AreChatControlsVisible));

                /// <summary> Disables encryption pipeline safely </summary>
                _pipeline?.DisableEncryption();

                /// <summary> Resets encryption init flag for clean future sessions </summary>
                Volatile.Write(ref _encryptionInitOnce, 0);
            }
            catch (Exception ex)
            {
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
        /// Expects the incoming public key in DER byte[] form.
        /// </summary>
        /// <param name="rosterEntries">
        /// The complete list of connected users as tuples of (UserId, Username, PublicKeyDer).
        /// </param>
        public void DisplayRosterSnapshot(
            IEnumerable<(Guid UserId, string Username, byte[] PublicKeyDer)> rosterEntries)
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
                    // Finds the corresponding tuple once and copies its DER bytes safely
                    var entry = rosterEntries.First(e => e.UserId == userId);
                    Users.Add(new UserModel
                    {
                        UID = userId,
                        Username = username,
                        PublicKeyDer = entry.PublicKeyDer ?? Array.Empty<byte>()
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
            /// For each joined user, only the username is needed for the notification.
            /// </summary>
            foreach (var (_, username) in joinedUsers)
            {
                Messages.Add($"# {username} {LocalizationManager.GetString("HasConnected")} #");
            }

            /// <summary>
            /// For each left user, only the username is needed for the notification.
            /// </summary>
            foreach (var (_, username) in leftUsers)
            {
                Messages.Add($"# {username} {LocalizationManager.GetString("HasDisconnected")} #");
            }

            // Refreshes the Users collection with the full, current roster
            Users.Clear();

            /// <summary>
            /// Iterates rosterEntries and assigns the DER public key directly to the user model.
            /// Ensures a non-null byte[] by falling back to Array.Empty<byte>().
            /// </summary>
            foreach (var (userId, username, publicKeyDer) in rosterEntries)
            {
                var safePublicKeyDer = publicKeyDer ?? Array.Empty<byte>();

                Users.Add(new UserModel
                {
                    UID = userId,
                    Username = username,
                    PublicKeyDer = safePublicKeyDer
                });
            }

            // Saves for next diff
            _previousRosterSnapshot = incomingSnapshot;
        }

        /// <summary>
        /// Handles a server-initiated disconnect command.  
        /// • Ensures the handler runs exactly once.  
        /// • Requests disconnect from the underlying server connection.  
        /// • Clears the user list and posts a localized system message to chat history.  
        /// • Notifies UI bindings so dependent logic updates.  
        /// • Performs cleanup without throwing from error paths.
        /// </summary>
        public void OnDisconnectedByServer()
        {
            /// <summary>
            /// Ensures the disconnect cleanup runs only once across threads.
            /// Uses Interlocked.Exchange to set the sentinel _clientDisconnecting to 1 and
            /// obtain the previous value in a single atomic operation.
            /// If the previous value was non-zero it means another thread already started
            /// the cleanup, so this call returns early to avoid double-closing sockets
            /// or duplicate UI updates.
            /// </summary>
            if (Interlocked.Exchange(ref _clientDisconnecting, 1) != 0)
            {
                return;
            }
      
            try
            {
                /// <summary> 
                /// Fire-and-forget attempts server-side disconnect
                /// The .ContinueWith(disconnectTask => { … }, TaskContinuationOptions.OnlyOnFaulted)
                /// means: “When the disconnect finishes, check if it had an error.
                /// Only run this extra code if something went wrong.”
                /// </summary>
                _ = _clientConn.DisconnectFromServerAsync().ContinueWith(disconnectTask =>
                {
                    if (disconnectTask.Exception != null)
                        ClientLogger.Log($"Async disconnect failed: {disconnectTask.Exception.InnerException?.Message}", ClientLogLevel.Error);
                }, TaskContinuationOptions.OnlyOnFaulted);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Error during server-initiated disconnect: {ex.Message}", ClientLogLevel.Error);
            }

            Application.Current.Dispatcher.Invoke(() =>
            {
                /// <summary> Removes all entries from the UI user list. </summary>
                Users.Clear();

                /// <summary> Appends a localized system message to the chat history </summary> 
                Messages.Add($"# {LocalizationManager.GetString("ServerHasClosed")} #");

                /// <summary> Notifies UI bindings so dependent logic refreshes </summary> 
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(WindowTitle));
                OnPropertyChanged(nameof(ConnectButtonText));
                OnPropertyChanged(nameof(AreCredentialsEditable));
                OnPropertyChanged(nameof(AreChatControlsVisible));

                /// <summary> Disables encryption pipeline safely </summary> 
                _pipeline?.DisableEncryption();

                /// <summary> Resets init flag for next session </summary>
                Volatile.Write(ref _encryptionInitOnce, 0);
            });
        }

        /// <summary>
        /// Handles an incoming encrypted message.
        /// Attempts decryption from the provided cipher bytes, resolves the sender's display name,
        /// and marshals the result onto the UI thread for display.
        /// </summary>
        /// <param name="senderUid">UID of the user who sent the message.</param>
        /// <param name="cipherBytes">Encrypted payload as a byte array.</param>
        private void OnEncryptedMessageReceived(Guid senderUid, byte[] cipherBytes)
        {
            if (cipherBytes == null || cipherBytes.Length == 0)
            {
                ClientLogger.Log($"Received empty ciphertext from {senderUid}", ClientLogLevel.Warn);
                return;
            }

            // Attempts decryption
            string plaintext = EncryptionHelper.DecryptMessageFromBytes(cipherBytes);

            // Resolves the sender's username using typed Guid comparison
            string username = Users?
                .FirstOrDefault(u => u.UID == senderUid)
                ?.Username
                ?? senderUid.ToString();

            // Posts the formatted message to the UI thread for insertion into the chat log
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
        /// Handles a received public-key event.
        /// Validates input, updates the KnownPublicKeys dictionary in a thread-safe manner,
        /// logs whether the key was added, updated, or duplicated,
        /// re-evaluates encryption readiness,
        /// and refreshes the UI lock icon if the client becomes ready.
        /// </summary>
        /// <param name="senderUid">The UID of the peer who provided the public key.</param>
        /// <param name="publicKeyDer">The RSA public key as a DER-encoded byte array.</param>
        public void OnPublicKeyReceived(Guid senderUid, byte[]? publicKeyDer)
        {
            // Discard if the key is missing or empty
            if (publicKeyDer == null || publicKeyDer.Length == 0)
            {
                ClientLogger.Log($"Discarded public key from {senderUid.ToString()} — key is null or empty.",
                    ClientLogLevel.Warn);
                return;
            }

            bool isNewOrUpdatedKey = false;

            // Protects the dictionary from concurrent writes
            lock (KnownPublicKeys)
            {
                if (KnownPublicKeys.TryGetValue(senderUid, out var existingKey))
                {
                    // Compares raw DER bytes for equality
                    if (existingKey != null && existingKey.Length == publicKeyDer.Length && existingKey.SequenceEqual(publicKeyDer))
                    {
                        ClientLogger.Log($"Duplicate public key for {senderUid.ToString()}; no change.",
                            ClientLogLevel.Debug);
                    }
                    else
                    {
                        // Replaces with the new DER bytes
                        KnownPublicKeys[senderUid] = publicKeyDer;
                        isNewOrUpdatedKey = true;
                        ClientLogger.Log($"Updated public key for {senderUid.ToString()}.",
                            ClientLogLevel.Info);
                    }
                }
                else
                {
                    // Registers a newly seen public key
                    KnownPublicKeys.Add(senderUid, publicKeyDer);
                    isNewOrUpdatedKey = true;
                    ClientLogger.Log($"Registered new public key for {senderUid.ToString()}.",
                        ClientLogLevel.Info);
                }
            }

            // Re-evaluates overall encryption state
            _pipeline.EvaluateEncryptionState();

            if (isNewOrUpdatedKey && IsEncryptionReady)
            {
                ClientLogger.Log($"Encryption readiness confirmed after registering key for {senderUid}.",
                    ClientLogLevel.Debug);
            }
            else if (isNewOrUpdatedKey && !IsEncryptionReady)
            {
                ClientLogger.Log("Key registered/updated, but encryption not ready yet — waiting for remaining peers.",
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
        /// • Handles a new user join event.
        /// • Reads the provided UID, username, and public key DER bytes.
        /// • Adds the user to the Users collection if not already present.
        /// • Registers the user’s public key and re-evaluates encryption state.
        /// • Posts a system notice to the chat UI on the dispatcher thread.
        /// </summary>
        /// <param name="uid">The joining user’s unique identifier.</param>
        /// <param name="username">The joining user’s display name.</param>
        /// <param name="publicKey">The joining user’s RSA public key as DER bytes.</param>
        public void OnUserConnected(Guid uid, string username, byte[] publicKey)
        {
            // Prevents duplicates
            if (Users.Any(u => u.UID == uid))
                return;

            // Builds the new user model
            var user = new UserModel
            {
                UID = uid,
                Username = username,
                PublicKeyDer = publicKey
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
                _pipeline.EvaluateEncryptionState();

                // Posts a system notice to the chat window
                Messages.Add($"# {username} {LocalizationManager.GetString("HasConnected")} #");
            });
        }

        /// <summary>
        /// Handles a user disconnect event (opcode: DisconnectNotify).
        /// Removes the specified user from the roster,
        /// updates the expected client count,
        /// and rechecks encryption readiness if enabled.
        /// </summary>
        /// <param name="uid">UID of the user who disconnected.</param>
        /// <param name="username">Display name of the user who disconnected.</param>
        public void OnUserDisconnected(Guid uid, string username)
        {
            try
            {
                // Locates the user by UID
                var user = Users.FirstOrDefault(u => u.UID == uid);
                if (user == null)
                    return;

                // Removes the user from the UI-bound list
                Users.Remove(user);

                // Updates the expected client count after removal
                ExpectedClientCount = Users.Count;
                ClientLogger.Log($"ExpectedClientCount updated — Total users: {ExpectedClientCount}", ClientLogLevel.Debug);

                // Rechecks encryption readiness when encryption is active
                if (Settings.Default.UseEncryption)
                {
                    if (_pipeline != null)
                    {
                        // Evaluates encryption state safely
                        _pipeline.EvaluateEncryptionState();
                    }
                    else
                    {
                        // Logs that pipeline is missing instead of throwing NullReferenceException
                        ClientLogger.Log("OnUserDisconnected detects null pipeline — skip EvaluateEncryptionState.", ClientLogLevel.Warn);
                    }
                }

                // Logs the disconnect event in a localized, simplified way
                ClientLogger.LogLocalized("ClientRemoved", ClientLogLevel.Info, username);
            }
            catch (Exception ex)
            {
                // Logs any unexpected failure in the disconnect handler
                ClientLogger.Log($"OnUserDisconnected handler fails: {ex.Message}", ClientLogLevel.Error);
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
        /// Resets all encryption-related flags and notifies the UI.
        /// This method is intended to be called by the EncryptionPipeline
        /// when encryption is disabled.
        /// </summary>
        public void ResetEncryptionFlags()
        {
            IsEncryptionReady = false;
            IsSyncingKeys = false;
            UseEncryption = false;
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
        /// Enables or disables encryption safely from the UI.
        /// Persists the new setting, validates that a user and connection exist,
        /// clears any local key material, then either:
        /// • Starts the asynchronous initialization pipeline in the background when enabling, or
        /// • Runs the synchronous disable path when disabling.
        /// If the pipeline fails, rolls back the setting and logs the error.
        /// </summary>
        /// <remark>
        /// MVVM Pattern : MainViewModel is the intermediary between the UI and business logic. 
        /// The pipeline should not be triggered directly by the UI, but via MainViewModel.
        /// </remark>
        /// <param name="enableEncryption">True to enable encryption, false to disable.</param>
        public void ToggleEncryption(bool enableEncryption)
        {
            bool previousValue = Settings.Default.UseEncryption;

            // Persists new preference immediately
            Settings.Default.UseEncryption = enableEncryption;
            Settings.Default.Save();

            // Validates presence of local user and active connection
            if (LocalUser == null || !IsConnected)
            {
                ClientLogger.Log("Encryption toggle failed – missing LocalUser or not connected.", ClientLogLevel.Warn);
                Settings.Default.UseEncryption = previousValue;
                OnPropertyChanged(nameof(UseEncryption));
                return;
            }

            // Clears any existing key material before proceeding
            KnownPublicKeys.Clear();
            LocalUser.PublicKeyDer = Array.Empty<byte>();
            LocalUser.PrivateKeyDer = Array.Empty<byte>();
            EncryptionHelper.ClearPrivateKey();

            bool pipelineSucceeded;

            if (enableEncryption)
            {
                // Notifies UI immediately
                OnPropertyChanged(nameof(UseEncryption));

                // Fire-and-forget: start pipeline in background without blocking UI
                _ = _pipeline.StartEncryptionPipelineBackground();

                // Optimistic success; actual result will be logged by background task
                pipelineSucceeded = true;
            }
            else
            {
                // Centralized disable path
                _pipeline.DisableEncryption();
                pipelineSucceeded = true;
            }

            if (!pipelineSucceeded)
            {
                ClientLogger.Log($"Encryption pipeline {(enableEncryption ? "init" : "teardown")} failed – rolling back.", ClientLogLevel.Error);
                Settings.Default.UseEncryption = previousValue;
                Settings.Default.Save();
                OnPropertyChanged(nameof(UseEncryption));
            }
            else
            {
                ClientLogger.Log(enableEncryption ? "Encryption enabled successfully." : "Encryption disabled successfully.", ClientLogLevel.Info);
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
    }
}
