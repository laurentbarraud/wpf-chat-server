/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 11th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.Net;
using chat_client.Properties;
using Hardcodet.Wpf.TaskbarNotification;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
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
        // PRIVATE FIELDS

        /// <summary>
        /// Tracks which users have already received our public RSA key.
        /// A HashSet is fast, especially for the Contains and Add operations.
        /// A UID can only be added once. This prevents redundant key transmissions.
        /// </summary>
        private readonly HashSet<Guid> _uidsKeySentTo = new();

        /// <summary>
        /// Backing field for the active client connection instance.
        /// Manages the network session and exposes connection state.
        /// </summary>
        private ClientConnection _clientConn;

        /// <summary>
        /// Atomic guard to ensure the client-side disconnect sequence runs only once.
        /// 0 = not running, 1 = already invoked.
        /// </summary>
        private int _clientDisconnecting = 0;

        /// <summary>
        /// Width of the connected users list.
        /// </summary>
        private double _connectedUsersListWidth = 182;

        /// <summary>
        /// Unified font size for conversations, connected users list,
        /// and message input field.
        /// </summary>
        private int _conversationsAndConnectedUsersTextSize = 14;

        /// <summary>
        /// Backing field that stores the default height value
        /// </summary>
        private int _emojiPanelHeight = 20;

        /// <summary>
        /// Stores the localized tooltip text shown when encryption is fully
        /// enabled and all required keys are available.
        /// </summary>
        private string _encryptionEnabledTooltip = "";

        /// <summary>
        /// Ensures that encryption initialization runs only once per session.
        /// Used as an interlocked flag: 0 = not initialized, 1 = already initialized.
        /// Reset to 0 during disconnect cleanup to allow fresh initialization.
        /// </summary>
        private int _encryptionInitOnce = 0;

        /// <summary>
        /// Backing field for the global font size setting used by the UI.
        /// </summary>
        private int _fontSizeSetting = 14;

        /// <summary>
        /// Backing field for the tooltip displayed when encryption keys are missing.
        /// </summary>
        private string _gettingMissingKeysTooltip = "";

        /// <summary>
        /// Stores the current theme selection state.
        /// Initialized from the saved AppTheme ("Dark" = true, otherwise false).
        /// </summary>
        private bool _isDarkTheme = Settings.Default.AppTheme == "Dark";

        /// <summary>
        /// Indicates whether the next roster snapshot is the very first update
        /// received after connecting. Suppresses join/leave notifications on first load.
        /// </summary>
        private bool _isFirstRosterSnapshot = true;

        /// <summary>
        /// Backing field for the font size applied to the message history.
        /// </summary>
        private int _messageFontSize = 14;

        /// <summary>
        /// Height of the message input TextBox.
        /// </summary>
        private double _messageInputHeight = 30;

        /// <summary>
        /// Holds the previous roster’s user IDs and usernames for diffing.
        /// </summary>
        private List<(Guid UserId, string Username)> _previousRosterSnapshot
            = new List<(Guid, string)>();

        /// <summary>
        /// Backing field for the font size applied to the connected users list.
        /// </summary>
        private int _userListFontSize = 14;

        /// <summary>
        /// Holds what the user types in the first textbox on top left of the MainWindow
        private string _username = string.Empty;

        /// <summary>
        /// Holds the current width of the MainWindow, used to compute layout‑dependent values.
        /// </summary>
        private int _windowWidth;

        // PROTECTED METHODS

        /// <summary>
        /// Notifies UI bindings that a property value has changed, enabling automatic interface updates.
        /// </summary>
        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        // PUBLIC PROPERTIES

        /// <summary>
        /// Gets the active client connection instance used by the ViewModel
        /// to manage the network session and monitor connection state.
        /// </summary>
        public ClientConnection ClientConn => _clientConn;

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
        /// Gets the reduced value of the current MainWindow width,
        /// returned as a pixel value for proportional UI sizing.
        /// </summary>
        public int BrdMessageInputWidth => (int)Math.Round(WindowWidth * 0.7);

        /// <summary>
        /// Connects or disconnects the client depending on the current connection state.
        /// Used by the main button and keyboard shortcuts.
        /// </summary>
        public RelayCommand ConnectDisconnectCommand { get; }

        /// <summary>
        /// Width of the connected users list.
        /// </summary>
        public double ConnectedUsersListWidth
        {
            get => _connectedUsersListWidth;
            private set
            {
                _connectedUsersListWidth = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Font size applied to conversation messages and connected users list.
        /// Updated whenever the user changes the setting in the popup.
        /// </summary>
        public int ConversationsAndConnectedUsersTextSize
        {
            get => _conversationsAndConnectedUsersTextSize;
            set
            {
                if (value < 12) value = 12;
                if (value > 20) value = 20;

                _conversationsAndConnectedUsersTextSize = value;
                OnPropertyChanged();

                // Saves to user settings
                Properties.Settings.Default.FontSizeSetting = value;
                Properties.Settings.Default.Save();

                // Updates dependent layout values
                MessageInputHeight = 30 + (value - 12) * 2;
                ConnectedUsersListWidth = ComputeConnectedUsersListWidth(value);
            }
        }

        /// <summary>
        /// Gets the dynamic emoji button size, proportional to the popup width.
        /// </summary>
        public int EmojiButtonSize => (int)Math.Round((EmojiPopupWidth / 12.0) * 0.85);

        /// <summary>
        /// Gets the dynamic emoji font size, proportional to the button size.
        /// </summary>
        public double EmojiFontSize => EmojiButtonSize * 0.55;

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
        /// Gets or sets the base height of the emoji panel.
        /// This value defines the default vertical size of the popup
        /// before any dynamic layout adjustments are applied.
        /// </summary>
        public int EmojiPanelHeight
        {
            get => _emojiPanelHeight;
            set => _emojiPanelHeight = value;
        }

        /// <summary>
        /// Gets the base height of the emoji popup, large enough
        /// to display square emoji buttons without vertical compression.
        /// </summary>
        public int EmojiPopupHeight => (int)Math.Round(EmojiButtonSize * 1.3) - 12;

        /// <summary>
        /// Gets the dynamic width of the emoji popup,
        /// computed as 90% of the message input field width.
        /// This keeps the popup proportionally sized when the window is resized.
        /// </summary>
        public int EmojiPopupWidth => (int)Math.Round(BrdMessageInputWidth * 0.90);

        /// <summary>
        /// Gets the dynamic emoji size, computed as one thirty‑second
        /// of the current emoji popup width.  
        /// This keeps emojis proportionally scaled as the popup resizes.
        /// </summary>
        public double EmojiSize => EmojiPopupWidth / 32.0;

        /// <summary>
        /// Gets or sets the localized tooltip text displayed when encryption
        /// is ready. This value is updated through localization and notifies
        /// the UI whenever it changes.
        /// </summary>
        public string EncryptionEnabledTooltip
        {
            get => _encryptionEnabledTooltip;
            set
            {
                _encryptionEnabledTooltip = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Provides access to the encryption pipeline instance,
        /// which manages key generation, publication, synchronization,
        /// and readiness evaluation for secure communication.
        /// </summary>
        public EncryptionPipeline EncryptionPipeline { get; private set; }

        /// <summary>
        /// Represents the number of clients expected to be connected for encryption readiness.
        /// This value is updated dynamically based on the current user list.
        /// </summary>
        public int ExpectedClientCount { get; set; } = 1; // Starts at 1 (self)

         /// <summary>
        /// Stores the current global font size selected by the user.
        /// This value is used as the base reference for updating all
        /// UI elements that support dynamic text scaling.
        /// </summary>
        public int FontSizeSetting
        {
            get => _fontSizeSetting;
            set
            {
                _fontSizeSetting = value;
                OnPropertyChanged();
            }
        }
        /// <summary>
        /// Gets or sets the localized tooltip text displayed when encryption
        /// keys are missing. This value is updated through localization and
        /// notifies the UI whenever it changes.
        /// </summary>
        public string GettingMissingKeysTooltip
        {
            get => _gettingMissingKeysTooltip;
            set
            {
                _gettingMissingKeysTooltip = value;
                OnPropertyChanged();
            }
        }

        public static string IPAddressOfServer { get; set; } = string.Empty;

        /// <summary>
        /// Proxy to the ClientConnection state.
        /// Ensures the UI binds to the actual TCP connection status.
        /// </summary>
        public bool IsConnected => _clientConn?.IsConnected ?? false;

        /// <summary>
        /// Proxy for UI binding.
        /// True when the encryption pipeline is ready.
        /// </summary>
        public bool IsEncryptionReady => EncryptionPipeline?.IsEncryptionReady == true;

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
                OnPropertyChanged(nameof(IsDarkTheme));

                // Saves the new theme preference
                Settings.Default.AppTheme = value ? "Dark" : "Light";
                Settings.Default.Save();

                // Applies the selected theme immediately
                ThemeManager.ApplyTheme(value);
            }
        }

        /// <summary>
        /// Represents the currently authenticated user.
        /// Is initialized to an empty User instance to satisfy non-nullable requirements.
        /// </summary>
        public UserModel LocalUser { get; private set; } = new UserModel();

        /// <summary>
        /// Font size used for rendering the conversation history on the right panel.
        /// Updated whenever the global font size setting changes.
        /// </summary>
        public int MessageFontSize
        {
            get => _messageFontSize;
            set
            {
                _messageFontSize = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Height of the message input TextBox.
        /// </summary>
        public double MessageInputHeight
        {
            get => _messageInputHeight;
            private set
            {
                _messageInputHeight = value;
                OnPropertyChanged();
            }
        }

        // What the user types in the textbox on bottom right
        // of the MainWindow in View gets stored in this property (bound in XAML).
        public static string MessageToSend { get; set; } = string.Empty;

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

                /// <summary> Persists new preference immediately </summary>
                Settings.Default.UseEncryption = value;
                Settings.Default.Save();

                /// <summary> Notifies UI bindings </summary>
                OnPropertyChanged(nameof(UseEncryption));

                /// <summary> Atomically trigger the pipeline toggle via ViewModel </summary>
                ToggleEncryption(value);
            }
        }

        /// <summary>
        /// Font size used for rendering the connected users list on the left panel.
        /// Updated whenever the global font size setting changes.
        /// </summary>
        public int UserListFontSize
        {
            get => _userListFontSize;
            set
            {
                _userListFontSize = value;
                OnPropertyChanged();
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

        /// <summary>
        /// Gets or sets the current width of the MainWindow.  
        /// This value is updated by the view and used to compute layout‑dependent properties.
        /// </summary>
        public int WindowWidth
        {
            get => _windowWidth;
            set
            {
                if (_windowWidth != value)
                {
                    _windowWidth = value;

                    /// <summary> Notifies WindowWidth </summary >
                    OnPropertyChanged();

                    /// <summary> Notifies dependent properties </summary>
                    OnPropertyChanged(nameof(BrdMessageInputWidth));
                    OnPropertyChanged(nameof(EmojiButtonSize));
                    OnPropertyChanged(nameof(EmojiFontSize));
                    OnPropertyChanged(nameof(EmojiPopupHeight));
                    OnPropertyChanged(nameof(EmojiPopupWidth));
                    OnPropertyChanged(nameof(EmojiSize));
                }
            }
        }

        /// <summary>
        /// Initializes the MainViewModel.
        /// Sets up collections, creates pipeline and connection,
        /// wires events, and configures UI commands.
        /// </summary>
        public MainViewModel()
        {
            /// <summary> Initializes collections bound to the UI </summary>
            Users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<string>();

            /// <summary> 
            /// Initializes tooltip strings used by the encryption status icon.
            /// These values are set to empty at startup and later populated
            /// through localization when the ViewModel loads.
            /// </summary>
            GettingMissingKeysTooltip = string.Empty;
            EncryptionEnabledTooltip = string.Empty;

            /// <summary> Creates client connection with dispatcher callback and reference to this ViewModel </summary>
            _clientConn = new ClientConnection(action => Application.Current.Dispatcher.BeginInvoke(action), this);

            /// <summary> Creates encryption pipeline with ViewModel and client connection </summary>
            EncryptionPipeline = new EncryptionPipeline(this, _clientConn,
                action => Application.Current.Dispatcher.BeginInvoke(action)
            );

            /// <summary> Relay pipeline PropertyChanged to proxy property for UI binding </summary>
            EncryptionPipeline.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(EncryptionPipeline.IsEncryptionReady))
                    OnPropertyChanged(nameof(IsEncryptionReady)); // Relais pour la UI
            };

            /// <summary> Binds the connection to the pipeline </summary>
            _clientConn.EncryptionPipeline = EncryptionPipeline;

            /// <summary> Subscribes to client connection events </summary>
            _clientConn.UserConnectedEvent += OnUserConnected;
            _clientConn.PlainMessageReceivedEvent += OnPlainMessageReceived;
            _clientConn.EncryptedMessageReceivedEvent += OnEncryptedMessageReceived;
            _clientConn.PublicKeyReceivedEvent += OnPublicKeyReceived;
            _clientConn.UserDisconnectedEvent += OnUserDisconnected;
            _clientConn.DisconnectedByServerEvent += OnDisconnectedByServer;

            /// <summary> Subscribes to language changes to refresh UI text </summary>
            Properties.Settings.Default.PropertyChanged += OnSettingsPropertyChanged;

            /// <summary> Creates Connect/Disconnect RelayCommand </summary>
            ConnectDisconnectCommand = new RelayCommand(
                () => { _ = ConnectDisconnectAsync(); },
                () => true
            );

            /// <summary>
            /// Creates ThemeTogglandCommand, which is bound to the UI toggle button.
            /// When executed, determines whether the dark theme is selected,
            /// updates the application settings accordingly, persists the choice,
            /// and applies the selected theme using ThemeManager class.
            /// </summary>
            ThemeToggleCommand = new RelayCommands<object>(param =>
            {
                /// <summary>
                /// Evaluates the toggle state parameter. 
                /// If true, dark theme is selected; otherwise, light theme is applied.
                /// </summary>
                bool isDarkThemeSelected = param is bool toggleState && toggleState;
                /// <remarks>
                /// "param is bool toggleState" is a pattern matching (introduced in C# 7).
                /// It tests if param is of type bool.
                /// If yes, it assigns the param value to a new local variable toggleState (of type bool).
                /// If not, the expression is false and toggleState is not initialized.
                /// "&& toggleState" ensures "toggleState" is only evaluated if the type check succeeds.
                /// </remarks>

                /// <summary>
                /// Updates the application theme setting ("Dark" or "Light") and saves it.
                /// </summary>
                Settings.Default.AppTheme = isDarkThemeSelected ? "Dark" : "Light";
                Settings.Default.Save();

                /// <summary> Applies the selected theme to the application./// </summary>
                ThemeManager.ApplyTheme(isDarkThemeSelected);
            });

            /// <summary> Reevaluates Connect/Disconnect command when connection state changes </summary>
            PropertyChanged += (sender, args) =>
            {
                if (args.PropertyName == nameof(IsConnected))
                {
                    ConnectDisconnectCommand.RaiseCanExecuteChanged();
                }
            };

            /// <summary> Loads saved font size </summary>
            int savedFontSize = Properties.Settings.Default.FontSizeSetting;

            // Applies it (this triggers all layout updates)
            ConversationsAndConnectedUsersTextSize = savedFontSize;
        }
        /// <summary>
        /// Calculates the appropriate width for the connected‑users list based on font size.
        /// </summary>
        private double ComputeConnectedUsersListWidth(int fontSize)
        {
            const int usernameLength = 24;
            double charWidth = fontSize * 0.28;
            double padding = 40;

            double predicted = (usernameLength * charWidth) + padding;

            double minWidth = 182;
            double maxWidth = 360;

            if (predicted < minWidth) return minWidth;
            if (predicted > maxWidth) return maxWidth;
            return predicted;
        }

        /// <summary>
        /// Orchestrates UI-side connection workflow:
        /// • validates username
        /// • delegates handshake to clientConn
        /// • initializes LocalUser
        /// • updates UI state and focus
        /// • initializes encryption if enabled (ensures proper key assignment and pipeline readiness)
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
                    _ = Application.Current.Dispatcher.BeginInvoke(() =>
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
                _ = Application.Current.Dispatcher.BeginInvoke(() =>
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
                        /// <summary> Ensures client connection exists first </summary>
                        _clientConn ??= new ClientConnection(action => 
                        Application.Current.Dispatcher.BeginInvoke(action), this);

                        /// <summary> Ensures pipeline exists before usage </summary>
                        if (EncryptionPipeline == null)
                        {
                            /// <summary> Creates encryption pipeline with ViewModel, client connection, and dispatcher </summary>
                            EncryptionPipeline = new EncryptionPipeline(this, _clientConn,
                                action => Application.Current.Dispatcher.BeginInvoke(action)
                            );

                            /// <summary> Bind connection to pipeline (bidirectional awareness if needed) </summary>
                            _clientConn.EncryptionPipeline = EncryptionPipeline;

                            ClientLogger.Log("EncryptionPipeline is created before usage.", ClientLogLevel.Debug);
                        }

                        /// <summary> Assigns in-memory RSA public key for this session </summary>
                        LocalUser.PublicKeyDer = EncryptionHelper.PublicKeyDer;
                        ClientLogger.Log($"LocalUser.PublicKeyDer assigned — length={LocalUser.PublicKeyDer?.Length}", ClientLogLevel.Debug);

                        /// <summary> Validates LocalUser.PublicKeyDer before use </summary>
                        if (LocalUser.PublicKeyDer == null || LocalUser.PublicKeyDer.Length == 0)
                        {
                            throw new InvalidOperationException("Public key not initialized");
                        }

                        /// <summary> Synchronizes the local public key with ClientConnection </summary>
                        _clientConn.LocalPublicKey = LocalUser.PublicKeyDer;

                        /// <summary> Delegates handshake completion and pipeline readiness </summary>
                        _clientConn.MarkHandshakeComplete(LocalUser.UID, LocalUser.PublicKeyDer);
                        ClientLogger.Log("Pipeline marked ready for session.", ClientLogLevel.Debug);

                        /// <summary> Publishes the local public key to the server </summary>
                        ClientLogger.Log("Sending public key to server...", ClientLogLevel.Debug);
                        await _clientConn.SendPublicKeyToServerAsync(LocalUser.UID, LocalUser.PublicKeyDer,
                        LocalUser.UID, cancellationToken).ConfigureAwait(false);
                        ClientLogger.Log("SendPublicKeyToServerAsync completed", ClientLogLevel.Debug);

                        /// <summary> Initializes local encryption context </summary>
                        ClientLogger.Log("Calling InitializeEncryptionAsync...", ClientLogLevel.Debug);
                        var encryptionInitOk = await EncryptionPipeline.InitializeEncryptionAsync(cancellationToken).ConfigureAwait(false);
                        ClientLogger.Log($"InitializeEncryptionAsync completed — SyncOk={encryptionInitOk}", ClientLogLevel.Debug);

                        /// <summary> Evaluates encryption state and notify UI if needed </summary>
                        var encryptionReady = EncryptionPipeline.EvaluateEncryptionState();
                        ClientLogger.Log($"EvaluateEncryptionState result — Ready={encryptionReady}", ClientLogLevel.Debug);
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"Encryption setup failed: {ex.Message}", ClientLogLevel.Error);
                    }
                }

                /// <summary> Restores focus to message input for immediate typing </summary>
                _ = Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                        mainWindow.TxtMessageInput.Focus();
                });

                /// <summary> Saves last used IP address for next session </summary>
                Settings.Default.LastIPAddressUsed = IPAddressOfServer;
                Settings.Default.Save();
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("Connection attempt canceled by user.", ClientLogLevel.Info);

                /// <summary> Resets UI state after cancellation </summary>
                _ = Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    ReinitializeUI();
                    OnPropertyChanged(nameof(IsConnected));
                });
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Fails to connect or handshake: {ex.Message}", ClientLogLevel.Error);

                /// <summary> Displays error and resets UI to disconnected state </summary>
                _ = Application.Current.Dispatcher.BeginInvoke(() =>
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
        /// Disconnects the client from the server.
        /// • Marks the disconnection as user-initiated to suppress "Server has closed" messages.  
        /// • Closes the TCP connection via clientConn.  
        /// • Clears UI state and notifies bindings.  
        /// • Disables encryption and resets init flags.  
        /// </summary>
        public void Disconnect()
        {
            try
            {
                /// <summary>
                /// Marks this disconnect as explicitly requested by the user.
                /// This flag will be checked later to suppress server-closed messages.
                /// </summary>
                _clientConn?.MarkUserInitiatedDisconnect();

                /// <summary>
                /// Closes the underlying TCP connection via the client connection.
                /// </summary>
                if (_clientConn?.IsConnected == true)
                {
                    _ = _clientConn.DisconnectFromServerAsync();
                }

                /// <summary>
                /// Clears all user/message data in the view.
                /// </summary>
                ReinitializeUI();

                /// <summary>
                /// Notifies UI bindings to reflect disconnected state.
                /// </summary>
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(WindowTitle));
                OnPropertyChanged(nameof(ConnectButtonText));
                OnPropertyChanged(nameof(AreCredentialsEditable));
                OnPropertyChanged(nameof(AreChatControlsVisible));

                /// <summary>
                /// Disables encryption pipeline safely.
                /// </summary>
                EncryptionPipeline?.DisableEncryption();

                /// <summary>
                /// Resets encryption init flag for clean future sessions.
                /// </summary>
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
        public void DisplayRosterSnapshot(IEnumerable<(Guid UserId, string Username, byte[] PublicKeyDer)> rosterEntries)
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
        /// • Suppresses all logic if the disconnect was explicitly requested by the user.  
        /// • Clears the user list and posts a localized system message to chat history (only if not user-initiated).  
        /// • Notifies UI bindings so dependent logic updates.  
        /// • Performs cleanup without throwing from error paths.  
        /// </summary>
        public void OnDisconnectedByServer()
        {
            /// <summary>
            /// Ensures the disconnect cleanup runs only once across threads.
            /// Uses Interlocked.Exchange to set the sentinel _clientDisconnecting to 1.
            /// If the previous value was non-zero, another thread already started cleanup,
            /// so this call returns early to avoid duplicate socket closing or UI updates.
            /// </summary>
            if (Interlocked.Exchange(ref _clientDisconnecting, 1) != 0)
            {
                return;
            }

            Application.Current.Dispatcher.BeginInvoke(() =>
            {
                /// <summary>
                /// Clears all entries from the UI user list.
                /// </summary>
                Users.Clear();

                /// <summary>
                /// Appends a localized system message to the chat history
                /// only if the disconnect was not explicitly requested by the user.
                /// </summary>
                Messages.Add($"# {LocalizationManager.GetString("DisconnectedByServer")} #");

                /// <summary>
                /// Notifies UI bindings so dependent logic refreshes.
                /// </summary>
                OnPropertyChanged(nameof(IsConnected));
                OnPropertyChanged(nameof(WindowTitle));
                OnPropertyChanged(nameof(ConnectButtonText));
                OnPropertyChanged(nameof(AreCredentialsEditable));
                OnPropertyChanged(nameof(AreChatControlsVisible));

                /// <summary>
                /// Resets the encryption initialization flag so that the next session
                /// starts with a clean state.
                /// </summary>
                Volatile.Write(ref _encryptionInitOnce, 0);
            });
        }

        /// <summary>
        /// Handles an incoming encrypted message.
        /// Always attempts decryption using the local RSA private key if available.
        /// Falls back to showing raw ciphertext only if the private key is missing.
        /// Updates the UI with the decrypted plaintext or logs an error.
        /// </summary>
        /// <param name="senderUid">Unique identifier of the message sender.</param>
        /// <param name="cipherBytes">Ciphertext payload received from the network.</param>
        public void OnEncryptedMessageReceived(Guid senderUid, byte[] cipherBytes)
        {
            /// <summary> Validates that ciphertext is non-empty </summary>
            if (cipherBytes == null || cipherBytes.Length == 0)
                return;

            /// <summary> Resolves sender name or falls back to UID string </summary>
            string username = Users.FirstOrDefault(u => u.UID == senderUid)?.Username
                              ?? senderUid.ToString();

            /// <summary> Checks if local private key material is available </summary>
            if (LocalUser?.PrivateKeyDer?.Length > 0)
            {
                try
                {
                    /// <summary> Decrypts ciphertext with local RSA private key </summary>
                    string plaintext = EncryptionHelper.DecryptMessageFromBytes(cipherBytes, LocalUser.PrivateKeyDer);


                    /// <summary> Posts decrypted message to UI thread </summary>
                    Application.Current.Dispatcher.BeginInvoke(() =>
                    {
                        Messages.Add($"{username}: {plaintext}");
                    });
                }
                catch (Exception ex)
                {
                    /// <summary> Logs decryption failure with exception details </summary>
                    ClientLogger.Log($"Decrypt failed for {senderUid}: {ex.Message}", ClientLogLevel.Error);

                    /// <summary> Posts failure placeholder to UI thread </summary>
                    Application.Current.Dispatcher.BeginInvoke(() =>
                    {
                        Messages.Add($"{username}: [decryption failed — {cipherBytes.Length} bytes]");
                    });
                }
            }
            else
            {
                /// <summary> Logs missing private key and shows raw ciphertext </summary>
                ClientLogger.Log("Private key missing; showing raw ciphertext.", ClientLogLevel.Warn);

                /// <summary> Posts raw ciphertext to UI thread as fallback </summary>
                Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    Messages.Add($"{username}: {Encoding.UTF8.GetString(cipherBytes)}");
                });
            }
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
                Application.Current.Dispatcher.BeginInvoke(() =>
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
        /// Handles a received public-key event from a peer.
        /// Ensures dictionary update and triggers re-evaluation.
        /// Also broadcasts the new key to other peers and requests missing keys.
        /// </summary>
        public void OnPublicKeyReceived(Guid senderUid, byte[]? publicKeyDer)
        {
            bool isNewOrUpdatedKey = false;

            /// <summary>
            /// Normalizes input: if null or empty, returns Array.Empty<byte>() 
            /// to represent clear mode.
            /// Ensures normalizedKey is always a valid byte[] (never null).
            /// </summary>
            var normalizedKey = (publicKeyDer == null || publicKeyDer.Length == 0)
                ? Array.Empty<byte>()
                : publicKeyDer;

            /// <summary>
            /// Ignores self-echo: do not register our own key again.
            /// </summary>
            if (senderUid == LocalUser.UID)
            {
                return;
            }

            /// <summary>
            /// Protects KnownPublicKeys dictionary with a lock to ensure thread safety.
            /// Updates or registers the key depending on whether it already exists.
            /// </summary>
            lock (EncryptionPipeline.KnownPublicKeys)
            {
                if (EncryptionPipeline.KnownPublicKeys.TryGetValue(senderUid, out var existingKey))
                {
                    /// <summary>
                    /// Compares the existing DER-encoded key bytes with the new key.
                    /// If they are identical, no update is performed.
                    /// </summary>
                    if (existingKey != null && existingKey.Length == normalizedKey.Length && existingKey.SequenceEqual(normalizedKey))
                    {
                        var displayName = Users.FirstOrDefault(u => u.UID == senderUid)?.Username
                                          ?? senderUid.ToString();
                        ClientLogger.Log($"Duplicate public key for {displayName}; no change.", ClientLogLevel.Debug);
                    }
                    else
                    {
                        /// <summary>
                        /// Updates the dictionary entry with the new DER-encoded key bytes.
                        /// </summary>
                        EncryptionPipeline.KnownPublicKeys[senderUid] = normalizedKey;
                        isNewOrUpdatedKey = true;

                        var displayName = Users.FirstOrDefault(u => u.UID == senderUid)?.Username
                                          ?? senderUid.ToString();
                        ClientLogger.Log($"Updated public key for {displayName}.", ClientLogLevel.Info);
                    }
                }
                else
                {
                    /// <summary>
                    /// Registers a newly seen public key for this sender.
                    /// </summary>
                    EncryptionPipeline.KnownPublicKeys.Add(senderUid, normalizedKey);
                    isNewOrUpdatedKey = true;

                    var displayName = Users.FirstOrDefault(u => u.UID == senderUid)?.Username
                                      ?? senderUid.ToString();
                    ClientLogger.Log($"Registered new public key for {displayName}.", ClientLogLevel.Info);
                }
            }

            if (isNewOrUpdatedKey)
            {
                /// <summary>
                /// Broadcasts the new key to all peers:
                /// - Sends our local key to each peer (so they can encrypt for us).
                /// - Sends each peer's key to the new sender (so it can encrypt for them).
                /// This ensures symmetric distribution of keys across all clients.
                /// </summary>
                foreach (var peer in Users.Where(u => u.UID != LocalUser.UID && u.UID != senderUid))
                {
                    // Sends our local key to existing peers
                    _ = _clientConn.SendPublicKeyToServerAsync(LocalUser.UID, LocalUser.PublicKeyDer!, peer.UID, CancellationToken.None);

                    // Sends each peer's key to the new client
                    if (EncryptionPipeline.KnownPublicKeys.TryGetValue(peer.UID, out var peerKey))
                    {
                        _ = _clientConn.SendPublicKeyToServerAsync(peer.UID, peerKey, senderUid, CancellationToken.None);
                    }
                }

                /// <summary>
                /// Re-evaluates encryption state after key distribution.
                /// Ensures that EncryptionReady is only set when all peer keys are present.
                /// </summary>
                ReevaluateEncryptionStateFromConnection();

                /// <summary>
                /// Logs encryption readiness state after key update.
                /// Helps diagnose whether all keys are present or still missing.
                /// </summary>
                if (EncryptionPipeline.IsEncryptionReady)
                {
                    ClientLogger.Log($"Encryption readiness confirmed after registering key for {senderUid}.", ClientLogLevel.Debug);
                }
                else
                {
                    ClientLogger.Log("Key registered/updated, but encryption not ready yet — waiting for remaining peers.", ClientLogLevel.Debug);
                }
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
        /// • Reads the provided UID, username, and public key DER bytes.
        /// • Adds the user to the Users collection if not already present.
        /// • Registers the user’s public key in the pipeline.
        /// • Re-evaluates encryption readiness via the pipeline.
        /// • Posts a system notice to the chat UI on the dispatcher thread.
        /// </summary>
        /// <param name="uid">The joining user’s unique identifier.</param>
        /// <param name="username">The joining user’s display name.</param>
        /// <param name="publicKey">The joining user’s RSA public key as DER bytes.</param>
        public void OnUserConnected(Guid uid, string username, byte[] publicKey)
        {
            /// <summary> Prevents duplicates by checking existing UIDs </summary>
            if (Users.Any(u => u.UID == uid))
                return;

            /// <summary> Builds the new user model </summary>
            var user = new UserModel
            {
                UID = uid,
                Username = username,
                PublicKeyDer = publicKey
            };

            /// <summary> Performs all UI-bound updates on the dispatcher thread </summary>
            Application.Current.Dispatcher.BeginInvoke(() =>
            {
                /// <summary> Adds the new user to the observable collection </summary>
                Users.Add(user);

                /// <summary> Updates expected client count and log the change </summary>
                ExpectedClientCount = Users.Count;
                ClientLogger.Log($"ExpectedClientCount updated — Total users: {ExpectedClientCount}", ClientLogLevel.Debug);

                /// <summary> Registers the public key in the pipeline if not already known </summary>
                if (!EncryptionPipeline.KnownPublicKeys.ContainsKey(uid))
                {
                    EncryptionPipeline.KnownPublicKeys[uid] = publicKey;
                    ClientLogger.Log($"Public key registered for {username} — UID: {uid}", ClientLogLevel.Debug);
                }

                /// <summary> Re-evaluates encryption readiness via pipeline </summary>
                EncryptionPipeline.EvaluateEncryptionState();

                /// <summary> Posts a system notice to the chat window </summary>
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
                    if (EncryptionPipeline != null)
                    {
                        // Evaluates encryption state safely
                        EncryptionPipeline.EvaluateEncryptionState();
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
        /// Public helper to trigger encryption readiness re-evaluation from connection layer.
        /// Encapsulates pipeline access and raises property change notifications so the UI updates.
        /// </summary>
        public void ReevaluateEncryptionStateFromConnection()
        {
            EncryptionPipeline?.EvaluateEncryptionState();

            // Ensures UI bindings refresh for IsEncryptionReady
            OnPropertyChanged(nameof(EncryptionPipeline.IsEncryptionReady));
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
        /// Resets all encryption-related flags and updates the UI bindings.
        /// Safe to call even if the pipeline is not yet initialized.
        /// </summary>
        public void ResetEncryptionPipelineAndUI()
        {
            if (EncryptionPipeline == null)
            {
                // Pipeline not yet initialized: just reset UI flags
                UseEncryption = false;
                OnPropertyChanged(nameof(EncryptionPipeline.IsEncryptionReady));
                OnPropertyChanged(nameof(UseEncryption));
                return;
            }

            EncryptionPipeline.SetEncryptionReady(false);
            EncryptionPipeline.SetSyncing(false);
            UseEncryption = false;

            OnPropertyChanged(nameof(EncryptionPipeline.IsEncryptionReady));
            OnPropertyChanged(nameof(UseEncryption));
        }

        /// <summary>
        /// Applies a red border style to the username textbox to visually indicate invalid input.
        /// </summary>
        private static void ShowUsernameError()
        {
            Application.Current.Dispatcher.BeginInvoke(() =>
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
        /// <param name="enableEncryption">True to enable encryption, false to disable.</param>
        public void ToggleEncryption(bool enableEncryption)
        {
            /// <summary> Stores the previous encryption setting for rollback if needed. </summary>
            bool previousValue = Settings.Default.UseEncryption;

            /// <summary> Persists the new preference immediately. </summary>
            Settings.Default.UseEncryption = enableEncryption;
            Settings.Default.Save();

            /// <summary> If not connected or no LocalUser, just persists the setting silently. </summary>
            if (LocalUser == null || !IsConnected)
            {
                OnPropertyChanged(nameof(UseEncryption));
                return;
            }

            /// <summary> Clears any existing key material before proceeding. </summary>
            EncryptionPipeline.KnownPublicKeys.Clear();
            LocalUser.PublicKeyDer = Array.Empty<byte>();
            LocalUser.PrivateKeyDer = Array.Empty<byte>();
            EncryptionHelper.ClearLocalPrivateKey();

            bool pipelineSucceeded;

            if (enableEncryption)
            {
                /// <summary> Notifies UI immediately when enabling encryption. </summary>
                OnPropertyChanged(nameof(UseEncryption));

                /// <summary>
                /// Fire-and-forget: start pipeline in background without blocking UI.
                /// Any errors are logged inside the pipeline; session remains alive.
                /// </summary>
                _ = Task.Run(async () =>
                {
                    bool encryptionInitOk = await EncryptionPipeline.InitializeEncryptionAsync(CancellationToken.None).ConfigureAwait(false);
                    if (!encryptionInitOk)
                    {
                        ClientLogger.Log("Encryption pipeline initialization failed.", ClientLogLevel.Warn);
                        Settings.Default.UseEncryption = previousValue;
                        Settings.Default.Save();
                        OnPropertyChanged(nameof(UseEncryption));
                    }
                });

                pipelineSucceeded = true; // optimistic; background task logs actual result
            }
            
            /// <summary> When disabling encryption </summary>
            else
            {
                EncryptionPipeline.DisableEncryption();
                pipelineSucceeded = true;
            }

            /// <summary> if pipeline failed synchronously </summary>
            if (!pipelineSucceeded)
            {
                /// <summary> Rolls back setting </summary>
                ClientLogger.Log($"Encryption pipeline {(enableEncryption ? "init" : "teardown")} failed – rolling back.", ClientLogLevel.Error);
                Settings.Default.UseEncryption = previousValue;
                Settings.Default.Save();
                OnPropertyChanged(nameof(UseEncryption));
            }
            else
            {
                /// <summary> Logs final success message for enable/disable operation. </summary>
                ClientLogger.Log(enableEncryption ? "Encryption enable requested." : "Encryption disabled successfully.", ClientLogLevel.Info);
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
