/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 9th, 2026</date>

using ChatClient.Helpers;
using ChatClient.MVVM.Model;
using ChatClient.MVVM.View;
using ChatClient.Net;
using ChatClient.Properties;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace ChatClient.MVVM.ViewModel
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
        /// Stores the application language currently selected by the user.
        /// Loaded from persisted settings at startup.
        /// </summary>
        private string _appLanguage = Properties.Settings.Default.AppLanguageCode;

        /// <summary>
        /// Backing field for the active client connection.
        /// Initialized immediately after establishing the TCP session and guaranteed
        /// to be non-null before any roster or message handling occurs.
        /// This follows the MVVM pattern where dependencies are assigned after
        /// construction, and the null-forgiving initialization is intentional.
        /// </summary>
        private ClientConnection _clientConn = null!;

        /// <summary>
        /// Holds the localized text displayed in the IP address field
        /// when the client is connected. 
        /// This replaces the normal placeholder and is centered and non‑italic. 
        /// </summary> 
        private string _connectedWatermarkText = "";

        /// <summary>
        /// Global unified font size setting for :
        /// - conversations
        /// - connected users list
        /// - username, ip address and message input field
        /// </summary>
        private int _displayFontSize = Settings.Default.DisplayFontSize;

        /// <summary>
        /// Backing field for the IP or connection status displayed in the UI.
        /// </summary>
        private string _currentIPDisplay = "";

        /// <summary>
        /// Ensures that encryption initialization runs only once per session.
        /// Used as an interlocked flag: 0 = not initialized, 1 = already initialized.
        /// Reset to 0 during disconnect cleanup to allow fresh initialization.
        /// </summary>
        private int _encryptionInitOnce = 0;

        /// <summary>
        /// Backing field for the height of the message input area (the text input field),
        /// excluding the emoji bar.
        /// </summary> 
        private double _inputAreaHeight = 34.0;

        /// <summary> 
        /// Holds the localized placeholder text displayed 
        /// in the IP address input field when it is empty and not focused.
        /// </summary> 
        private string _ipAddressWatermarkText = "";

        /// <summary>
        /// Stores the current theme selection state.
        /// Initialized from the saved AppTheme ("dark" = true, otherwise false).
        /// </summary>
        private bool _isDarkTheme = Settings.Default.AppTheme == "dark";

        /// <summary> 
        /// Indicates whether the application is running in debug mode.
        /// Used to control the visibility and animation behavior of developer‑only UI elements.
        /// </summary>
        private bool _isDebugMode;

        /// <summary>
        /// Indicates whether the next roster snapshot is the first update
        /// received after connecting. Used to suppress join/leave notifications
        /// and to detect whether the roster is stable for solo-mode encryption.
        /// </summary>
        private bool _isFirstRosterSnapshot = true;

        /// <summary>
        /// Holds the previous roster’s user IDs and usernames for diffing.
        /// </summary>
        private List<(Guid UserId, string Username)> _previousRosterSnapshot
            = new List<(Guid, string)>();

        /// <summary> 
        /// Stores the computed pixel width of the message input field. 
        /// Initialized to 400 so the field has a reasonable default width size. 
        /// </summary> 
        private double _messageInputFieldWidth = 400.0; 

        /// <summary> 
        /// Backing field storing the watermark text displayed in the message 
        /// input field when empty. 
        /// </summary>
        private string _messageInputFieldWatermarkText = "";

        /// <summary>
        /// Backing field storing the current message being composed by the user 
        /// before it is sent.
        /// </summary>
        private string _messageToSend = string.Empty;

        /// <summary> Backing field storing the title of the monitor window.</summary>
        private string _monitorWindowTitle = string.Empty;

        /// <summary>
        /// Stores the last known value of AllKeysValid
        /// so the lock animation only runs on state changes.
        /// </summary>
        private bool _previousAllKeysValid;

        /// <summary>
        /// Backing field storing the current computed width of the right panel.
        /// Updated whenever the window is resized.
        /// </summary>
        private double _rightGridWidth;

        /// <summary>
        /// Backing field storing the base color used for the background of
        /// bubbles representing messages sent by the local user.
        /// </summary>
        private double _sentBubbleHue = 185.0;

        /// <summary>
        /// Backing field for the server IP address used when the client is disconnected.
        /// This value is bound in TwoWay mode to allow user input and is initialized from application settings.
        /// </summary>
        private string _serverIPAddress = Settings.Default.ServerIPAddress;

        /// <summary> Backing field storing the title of the settings window.</summary>
        private string _settingsWindowTitle = string.Empty;

        /// <summary> Blocks roster notifications during initialization. </summary>
        private bool _suppressRosterNotifications = true;

        /// <summary>
        /// Indicates whether the user explicitly initiated a disconnect action.
        /// Used to suppress automatic "You have been disconnected" notifications
        /// and to avoid echo notifications after reconnect.
        /// </summary>
        private bool _userHasClickedOnDisconnect = false;

        /// <summary>
        /// Holds what the user types in the first textbox on top left of the MainWindow
        /// </summary>
        private string _username = string.Empty;

        /// <summary> 
        /// Holds the localized placeholder text displayed in the username input field 
        /// when it is empty and not focused. 
        /// </summary> 
        private string _usernameWatermarkText = "";

        /// <summary>
        /// Brush used to render watermark text. Its color adapts to the current theme:
        /// a darker grey in light mode and a lighter grey in dark mode.
        /// </summary>
        private SolidColorBrush _watermarkBrush = new SolidColorBrush(Color.FromRgb(128, 128, 128)) { Opacity = 0.45 };

        // PUBLIC PROPERTIES

        /// <summary>
        /// True when all known public keys are valid.
        /// Does not depend on user settings or connection state.
        /// </summary>
        public bool AllKeysValid => EncryptionPipeline.KnownPublicKeys.Count > 0 &&
            EncryptionPipeline.KnownPublicKeys.All(k => k.IsValid);

        /// <summary>
        /// Application UI language code.
        /// Persists user choice, reloads resources, and updates UI labels.
        /// </summary>
        public string AppLanguage
        {
            get => _appLanguage;
            set
            {
                if (_appLanguage == value)
                    return;

                _appLanguage = value;

                // Persists the new language choice
                Properties.Settings.Default.AppLanguageCode = value;
                Properties.Settings.Default.Save();

                OnPropertyChanged(nameof(AppLanguage));

                // Reloads localization resources
                LocalizationManager.InitializeLocalization(value);

                // Refreshes localized DisplayName for each language option
                RefreshLanguageOptions();

                // Updates watermark images
                InitializeWatermarkResources();
            }
        }

        public string AppLanguageLabel => LocalizationManager.GetString("AppLanguageLabel");

        /// <summary>
        /// Gets the active client connection used by the ViewModel to manage the
        /// network session and monitor connection state. The underlying field is
        /// initialized right after establishing the TCP session and is guaranteed
        /// to be non-null for the lifetime of the ViewModel.
        /// </summary>
        public ClientConnection ClientConn => _clientConn;

        public string AboutThisSoftwareLabel => LocalizationManager.GetString("AboutThisSoftwareLabel");

        /// <summary>
        /// Localized header text for the action column in the monitor grid.
        /// </summary>
        public string ActionHeader => LocalizationManager.GetString("ActionHeader");

        /// <summary> 
        /// Base emoji button size (minimum), derived from display font and height scale. 
        /// </summary> 
        private double BaseEmojiButtonSize => DisplayFontSize * HeightScaleFactor * 0.6;

        private double BaseEmojiFontSize => 14;
        
        /// <summary>
        /// Computes the dynamic height of the Connect/Disconnect button based on the
        /// current global font size. 
        /// The height scales proportionally and increases up.
        /// </summary>
        public double ConnectDisconnectButtonHeight
        {
            get
            {
                // Computes the raw height before proportional scaling
                double baseHeight = DisplayFontSize * HeightScaleFactor;

                // Normalizes the current font size into a 0–1 progression ratio
                double ratio = (DisplayFontSize - MinDisplayFontSize) /
                               (MaxDisplayFontSize - MinDisplayFontSize);

                // Ensures the ratio stays within valid bounds
                ratio = Math.Clamp(ratio, 0, 1);

                // Applies a progressive height increase up to +40% at maximum font size
                double increaseFactor = 1 + (ratio * 0.40);

                // Final computed height
                return baseHeight * increaseFactor;
            }
        }

        /// <summary>
        /// Connects or disconnects the client depending on the current connection state.
        /// Used by the main button and keyboard shortcuts.
        /// </summary>
        public RelayCommand ConnectDisconnectCommand { get; }

        /// <summary> 
        /// Gets or sets the localized text displayed in the IP address field
        /// when the client is connected. 
        /// This replaces the normal placeholder. 
        /// </summary>
        public string ConnectedWatermarkText
        {
            get => _connectedWatermarkText;
            set
            {
                _connectedWatermarkText = value;

                OnPropertyChanged(nameof(ConnectedWatermarkText));
            }
        }

        /// <summary>
        /// Provides the IP address text to display in the UI.
        /// When connected, shows a localized "Connected" label.
        /// When disconnected, shows the last used server IP.
        /// </summary>
        public string CurrentIPDisplay
        {
            get => _currentIPDisplay;
            set
            {
                if (_currentIPDisplay != value)
                {
                    _currentIPDisplay = value;

                    OnPropertyChanged(nameof(CurrentIPDisplay));
                }
            }
        }

        /// <summary>
        /// Stores the current global font size applied to conversation messages,
        /// the input field, and the connected users list.
        /// </summary>
        public int DisplayFontSize
        {
            get => _displayFontSize;
            set
            {
                int clampedFontSizeValue = Math.Clamp(value, 12, 36);

                if (_displayFontSize == clampedFontSizeValue)
                    return;

                _displayFontSize = clampedFontSizeValue;

                // Forces WPF to refresh all message templates and input field visuals.
                // This triggers a full re-evaluation of DataTemplates, re-applies FontSize bindings,
                // updates already-rendered bubble messages or raw-text messages.
                OnPropertyChanged(nameof(DisplayFontSize));

                // Notifies dependent UI elements
                OnPropertyChanged(nameof(UsernameAndIPAddressInputFieldHeight));
                OnPropertyChanged(nameof(ConnectDisconnectButtonHeight));
                OnPropertyChanged(nameof(Messages));

                // Persists user preference
                Properties.Settings.Default.DisplayFontSize = clampedFontSizeValue;
                Properties.Settings.Default.Save();
            }
        }

        /// <summary>
        /// Gets the localized font size label text
        /// </summary>
        public string DisplayFontSizeLabel => LocalizationManager.GetString("DisplayFontSizeLabel");

        /// <summary> 
        /// Proportional emoji button size. 
        /// </summary> 
        public int EmojiButtonSize => (int)Math.Round(BaseEmojiButtonSize * EmojiScaleFactor);

        /// <summary> 
        /// Proportional emoji font size. 
        /// </summary> 
        public double EmojiFontSize => BaseEmojiFontSize * EmojiScaleFactor;

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
        /// Gets the base height of the emoji popup, large enough
        /// to display square emoji buttons without vertical compression.
        /// </summary>
        public int EmojiPopupHeight => (int)Math.Round(EmojiButtonSize * 1.4);

        /// <summary>
        /// Gets the dynamic width of the emoji popup,
        /// computed as 90% of the message input field width.
        /// This keeps the popup proportionally sized when the window is resized.
        /// </summary>
        public int EmojiPopupWidth => (int)Math.Round(MessageInputFieldWidth * 0.99);

        /// <summary>
        /// Gets a proportional scale factor based on the width of the message input field.
        /// Linear growth: minimum = 1.15, maximum = 1.495.
        /// </summary>
        private double EmojiScaleFactor
        {
            get
            {
                const double emojiReferenceWidth = 100.0;   // width where emojis start growing
                const double maxWidthHandled = 900.0;       // width where emojis reach their maximum size

                const double minScale = 1;               // emoji size when the field is small
                const double maxScale = 2;              // emoji size when the field is very wide

                double msgInputWidth = MessageInputFieldWidth;

                // If the field is smaller than the reference width → use the minimum size
                if (msgInputWidth <= emojiReferenceWidth)
                {
                    return minScale;
                }

                // If the field is larger than the maximum width → use the maximum size
                if (msgInputWidth >= maxWidthHandled)
                {
                    return maxScale;
                }

                // Ratio tells us "how far we are" between small and large
                // 0.0 = at reference width, 1.0 = at max width
                double ratio = (msgInputWidth - emojiReferenceWidth) / (maxWidthHandled - emojiReferenceWidth);

                // Grows the emoji size smoothly between minScale and maxScale
                return minScale + ratio * (maxScale - minScale);
            }
        }

        public string EncryptionEnabledToolTip => LocalizationManager.GetString("EncryptionEnabledToolTip");

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

        public string GettingMissingKeysToolTip => LocalizationManager.GetString("GettingMissingKeysToolTip");

        /// <summary>
        /// Base multiplier used to convert the global font size into a consistent control height.
        /// </summary>
        public double HeightScaleFactor { get; } = 2.2;

        /// <summary> 
        /// Stores the height of the message input area (the text input field). 
        /// This value is updated live by the splitter and persisted in user settings.
        /// </summary> 
        public double InputAreaHeight 
        { 
            get => _inputAreaHeight; 
            set 
            { 
                // Enforces minimum height
                double clampedValue = Math.Max(value, 34.0);

                if (Math.Abs(_inputAreaHeight - clampedValue) < 0.1)
                {
                    return; 
                } 
                _inputAreaHeight = clampedValue; 
                OnPropertyChanged(); 

                Settings.Default.InputAreaHeight = clampedValue;
                Settings.Default.Save(); 
            } 
        }

        /// <summary> 
        /// Gets or sets the localized placeholder text for the IP address field. 
        /// Displayed when the field is empty and not focused. </summary> 
        public string IPAddressWatermarkText 
        { 
            get => _ipAddressWatermarkText; 
            set { _ipAddressWatermarkText = value; 
                
                OnPropertyChanged(nameof(IPAddressWatermarkText)); 
            } 
        }

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
                if (_isDarkTheme == value)
                {
                    return;
                }
                
                _isDarkTheme = value;
                OnPropertyChanged();

                // Saves the new theme preference
                Settings.Default.AppTheme = value ? "dark" : "light";
                Settings.Default.Save();

                // Applies the selected theme immediately
                ThemeManager.ApplyTheme(value);
            }
        }

        /// <summary>
        /// Exposes whether the initial roster snapshot has already been processed.
        /// True only until the first roster update is received.
        /// </summary>
        public bool IsFirstRosterSnapshot => _isFirstRosterSnapshot;

        /// <summary> True when the 
        /// should be visible. </summary> 
        public bool IsGridVisible => MaskMessage == null;

        /// <summary> True when a mask message should be displayed instead of the grid. </summary>
        public bool IsMaskVisible => MaskMessage != null;

        /// <summary>
        /// Indicates whether the application is running in a debug build,
        /// enabling developer‑only UI elements and diagnostics.
        /// </summary>
        public bool IsDebugMode
        {
            get => _isDebugMode;
            set
            {
                _isDebugMode = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Localized header text for the key excerpt column in the monitor grid.
        /// </summary>
        public string KeyExcerptHeader => LocalizationManager.GetString("KeyExcerptHeader");

        /// <summary> 
        /// Raised whenever the application language changes. 
        /// ViewModels that expose localized properties can subscribe to 
        /// this event to refresh their UI strings in real time.
        /// </summary>
        public event EventHandler? LanguageChanged;

        /// <summary>
        /// Represents the currently authenticated user.
        /// Is initialized to an empty User instance to satisfy non-nullable requirements.
        /// </summary>
        public UserModel LocalUser { get; private set; } = new UserModel();

        /// <summary>
        /// Gets the current mask message to display over the monitor grid.
        /// Returns null when no mask should be shown.
        /// </summary>
        public string? MaskMessage
        {
            get
            {
                if (!Settings.Default.UseEncryption)
                {
                    return LocalizationManager.GetString("EnableEncryptionToSeePublicKeysState");
                }

                if (!IsConnected)
                {
                    return LocalizationManager.GetString("NotConnected");
                }

                return null;
            }
        }

        /// <summary>
        /// Gets the maximum font size allowed for UI text scaling.
        /// </summary>
        public int MaxDisplayFontSize => 36;

        /// <summary>
        /// Computes the pixel offset of the message input field based on the right
        /// panel width and the user-defined percentage.
        /// </summary>
        public double MessageInputFieldLeftOffset
        {
            get
            {
                double rawOffset = RightGridWidth * (MessageInputFieldLeftOffsetPercent / 100.0);

                double maxOffset = RightGridWidth - MessageInputFieldWidth;

                if (maxOffset < 0)
                    maxOffset = 0;

                return Math.Min(rawOffset, maxOffset);
            }
        }

        /// <summary>
        /// Gets the localized label text for the message input field's left offset slider.
        /// </summary>
        public string MessageInputFieldLeftOffsetLabel => LocalizationManager.GetString("MessageInputFieldLeftOffsetLabel");

        /// <summary>
        /// Stores the percentage (1–100) of horizontal offset applied to the message
        /// input field within the right panel. The value is persisted in application settings.
        /// </summary>
        public double MessageInputFieldLeftOffsetPercent
        {
            get
            {
                double storedLeftOffsetPercent = Properties.Settings.Default.MessageInputFieldLeftOffsetPercent;

                return Math.Clamp(storedLeftOffsetPercent, 0.0, 100.0);
            }
            set
            {
                double clampedValue = Math.Clamp(value, 0.0, 100.0);

                if (Math.Abs(clampedValue - Properties.Settings.Default.MessageInputFieldLeftOffsetPercent) < 0.01)
                    return;

                Properties.Settings.Default.MessageInputFieldLeftOffsetPercent = clampedValue;
                Properties.Settings.Default.Save();

                OnPropertyChanged(nameof(MessageInputFieldLeftOffsetPercent));
                OnPropertyChanged(nameof(MessageInputFieldLeftOffset));
                OnPropertyChanged(nameof(MessageInputFieldMargin));
            }
        }
        
        /// <summary>
        /// Converts the computed left offset into a Thickness margin.
        /// </summary>
        public Thickness MessageInputFieldMargin
        {
            get
            {
                return new Thickness(MessageInputFieldLeftOffset, 0, 0, 0);
            }
        }

        /// <summary> 
        /// Localized watermark text displayed in the message input field when empty. </summary> 
        public string MessageInputFieldWatermarkText
        {
            get => _messageInputFieldWatermarkText;
            set
            {
                if (_messageInputFieldWatermarkText != value)
                {
                    _messageInputFieldWatermarkText = value;

                    OnPropertyChanged();
                }
            }
        }

        /// <summary> 
        /// Computes the actual pixel width of the message input field based 
        /// on the right panel width and the user-defined percentage. 
        /// </summary> 
        public double MessageInputFieldWidth
        {
            get
            {
                // If the right panel is too small, enforces a minimum width
                if (RightGridWidth <= 100)
                {
                    return 100;
                }
                // Computes width based on the percentage chosen by the user
                return RightGridWidth * (MessageInputFieldWidthPercent / 100.0);
            }
            set
            {
                if (Math.Abs(_messageInputFieldWidth - value) < 0.1)
                {
                    return;
                }

                _messageInputFieldWidth = value;

                // Notifies dependent properties
                OnPropertyChanged(nameof(EmojiScaleFactor)); 
                OnPropertyChanged(nameof(EmojiButtonSize)); 
                OnPropertyChanged(nameof(EmojiPopupWidth)); 
            } 
        }

        public string MessageInputFieldWidthLabel => LocalizationManager.GetString("MessageInputFieldWidthLabel");

        /// <summary>
        /// Stores the percentage (1–100) of the right panel width allocated
        /// to the message input field. The value is clamped to prevent the
        /// input field from collapsing, and is persisted in application settings.
        /// </summary>
        public double MessageInputFieldWidthPercent
        {
            get
            {
                double storedWidthPercent = Properties.Settings.Default.MessageInputFieldWidthPercent;

                if (storedWidthPercent <= 0)
                    storedWidthPercent = 60.0;

                return Math.Clamp(storedWidthPercent, 1.0, 100.0);
            }
            set
            {
                double clampedValue = Math.Clamp(value, 1.0, 100.0);

                if (Math.Abs(clampedValue - Properties.Settings.Default.MessageInputFieldWidthPercent) < 0.01)
                {
                    return;
                }

                Properties.Settings.Default.MessageInputFieldWidthPercent = clampedValue;
                Properties.Settings.Default.Save();

                OnPropertyChanged(nameof(MessageInputFieldWidthPercent));
                OnPropertyChanged(nameof(MessageInputFieldWidth));
                OnPropertyChanged(nameof(MessageInputFieldLeftOffset));
                OnPropertyChanged(nameof(MessageInputFieldMargin));
                OnPropertyChanged(nameof(EmojiPopupWidth));
            }
        }

        /// <summary>
        /// Gets or sets the message currently typed by the user. This value is bound
        /// to the message input TextBox and is cleared automatically after a successful send.
        /// </summary>
        public string MessageToSend
        {
            get => _messageToSend;
            set
            {
                if (_messageToSend != value)
                {
                    _messageToSend = value;
                    OnPropertyChanged();
                }
            }
        }
        /// <summary>
        /// Represents a dynamic collection of chat messages that notifies the UI
        /// when items are added, removed, or when the entire list is refreshed.
        /// Each entry is a ChatMessage containing text, sender information,
        /// timestamp, and display flags.
        /// </summary>
        public ObservableCollection<ChatMessage> Messages { get; set; }
            = new ObservableCollection<ChatMessage>();

        /// <summary>
        /// Minimum font size allowed for UI text scaling.
        /// </summary>
        public static int MinDisplayFontSize => 12;

        /// <summary> Localized text displayed when a public key is missing or invalid. </summary> 
        public string MissingOrInvalidPublicKey { get; private set; } = string.Empty;

        /// <summary>
        /// Notifies the UI that a property value has changed.
        /// </summary>
        /// <param name="propertyName">The name of the changed property.</param>
        public void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <summary> Localized text for the monitor window title. </summary>
        public string MonitorWindowTitle
        {
            get => _monitorWindowTitle;
            set
            {
                _monitorWindowTitle = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Gets the localized label text for the incoming bubble color setting
        /// </summary>
        public string OutgoingBubbleColorLabel => LocalizationManager.GetString("OutgoingBubbleColorLabel");

        /// <summary>
        /// Gets or sets the port number used by the client.
        /// This property acts as a proxy to the underlying application settings.
        /// </summary>
        public int PortNumber
        {
            get => Settings.Default.PortNumber;
            set
            {
                if (Settings.Default.PortNumber != value)
                {
                    Settings.Default.PortNumber = value;
                    OnPropertyChanged();
                }
            }
        }

        /// <summary>
        /// Event triggered when a property value changes, used to notify bound UI elements in data-binding scenarios.
        /// Implements the INotifyPropertyChanged interface to support reactive updates in WPF.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Proxy-property: gets or sets the application setting
        /// controlling whether raw text mode is enabled.
        /// </summary>
        public bool RawTextMode
        {
            get => Settings.Default.RawTextMode;
            set
            {
                if (Settings.Default.RawTextMode == value)
                {
                    return;
                }

                Settings.Default.RawTextMode = value;
                Settings.Default.Save();

                // Notifies UI bindings
                OnPropertyChanged();

                // Forces the view to re-evaluate templates
                var view = CollectionViewSource.GetDefaultView(Messages); 
                view?.Refresh();
            }
        }

        public string RawTextModeLabel => LocalizationManager.GetString("RawTextModeLabel");

        /// <summary>
        /// Determines whether the application should minimize to the system tray.
        /// </summary>
        public bool ReduceToTray
        {
            get => Properties.Settings.Default.ReduceToTray;
            set
            {
                if (Properties.Settings.Default.ReduceToTray == value)
                    return;

                Properties.Settings.Default.ReduceToTray = value;
                Properties.Settings.Default.Save();

                OnPropertyChanged(); // CallerMemberName: "ReduceToTray"
            }
        }

        /// <summary>
        /// Gets the localized reduce to tray label text
        /// </summary>
        public string ReduceToTrayLabel => LocalizationManager.GetString("ReduceToTrayLabel");

        /// <summary> 
        /// Command bound to the action button in the monitor grid. 
        /// Sends a targeted request for the missing public key of the selected user, 
        /// using the UID as the command parameter. 
        /// </summary>
        public ICommand RequestMissingPublicKeyCommand { get; } = null!;

        /// <summary>
        /// Represents the current pixel width of the right panel. 
        /// This value is updated automatically whenever the panel is resized 
        /// and is used as the basis for computing proportional UI elements 
        /// such as the message input field width and its horizontal offset.
        /// </summary>

        public double RightGridWidth
        {
            get => _rightGridWidth;
            set
            {
                if (Math.Abs(_rightGridWidth - value) < 0.5)
                    return;

                _rightGridWidth = value;

                OnPropertyChanged(nameof(RightGridWidth));
                OnPropertyChanged(nameof(MessageInputFieldWidth));
                OnPropertyChanged(nameof(MessageInputFieldLeftOffset));
                OnPropertyChanged(nameof(MessageInputFieldMargin));
            }
        }

        /// <summary>
        /// Gets or sets the hue value (0–360°) used to compute the color
        /// of outgoing message bubbles. This value is updated by the slider
        /// in the settings window and persisted in application settings.
        /// </summary>
        public double SentBubbleHue
        {
            get => _sentBubbleHue;
            set
            {
                if (_sentBubbleHue == value) 
                { 
                    return;
                }

                _sentBubbleHue = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(SentBubbleBackgroundBrush));

                Settings.Default.SentBubbleHue = value;
                Settings.Default.Save();
            }
        }

        /// <summary> Localized text for the settings window title. </summary>
        public string SettingsWindowTitle
        {
            get => _settingsWindowTitle;
            set
            {
                _settingsWindowTitle = value;
                OnPropertyChanged();
            }
        }

        public string ScrollLeftToolTip => LocalizationManager.GetString("ScrollLeftToolTip");
        public string ScrollRightToolTip => LocalizationManager.GetString("ScrollRightToolTip");

        /// <summary>
        /// Gets the brush representing the current outgoing bubble color,
        /// computed from the selected hue value.
        /// </summary>
        public SolidColorBrush SentBubbleBackgroundBrush
        {
            get => new SolidColorBrush(ColorFromHue(SentBubbleHue));
        }

        /// <summary>
        /// Property used by the IP address TextBox when the client is disconnected.
        /// This value is bound in TwoWay mode to allow user editing.
        /// When connected, the TextBox switches to a read-only binding on CurrentIPDisplay.
        /// The actual persisted value comes from Settings.Default.ServerIPAddress,
        /// which acts as the single source of truth for the saved server IP.
        /// </summary>
        public string ServerIPAddress
        {
            get => _serverIPAddress;
            set
            {
                _serverIPAddress = value;
                OnPropertyChanged();
            }
        }

        public string SettingsToolTip => LocalizationManager.GetString("SettingsToolTip");


        /// <summary>
        /// Collection of languages for the ComboBox (ISO code + localized name).
        /// </summary>
        public ObservableCollection<LanguageOptions> SupportedLanguages { get; }
            = new ObservableCollection<LanguageOptions>
            {
                new LanguageOptions("en"),
                new LanguageOptions("fr"),
                new LanguageOptions("es"),
            };

        /// <summary>
        /// Localized header text for the status column in the monitor grid.
        /// </summary>
        public string StatusHeader => LocalizationManager.GetString("StatusHeader");

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
                {
                    return;
                }

                Settings.Default.UseEncryption = value;
                Settings.Default.Save();

                // Notifies UI bindings
                OnPropertyChanged();

                // Atomically triggers the pipeline toggle via ViewModel.
                ToggleEncryptionState(value);
            }
        }

        /// <summary>
        /// Gets the localized use encryption for messages label text
        /// </summary>
        public string UseEncryptionLabel => LocalizationManager.GetString("UseEncryptionLabel");

        /// <summary>True if the user triggered a disconnect.</summary>
        public bool UserHasClickedOnDisconnect
        {
            get => _userHasClickedOnDisconnect;
            set
            {
                if (_userHasClickedOnDisconnect == value)
                    return;

                _userHasClickedOnDisconnect = value;
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
        /// Computes the dynamic height of username and IP input fields, scaling up to +30% at maximum font size.
        /// </summary>
        public double UsernameAndIPAddressInputFieldHeight
        {
            get
            {
                // Base height derived from the global font size
                double baseHeight = DisplayFontSize * HeightScaleFactor;

                // Normalized ratio (0–1) representing how far the slider is between min and max font size
                double ratio = (DisplayFontSize - MinDisplayFontSize) /
                               (MaxDisplayFontSize - MinDisplayFontSize);

                // Ensures the ratio stays within valid bounds
                ratio = Math.Clamp(ratio, 0, 1);

                // Applies a progressive increase up to +30% at maximum font size
                return baseHeight * (1 + ratio * 0.30);
            }
        }

        /// <summary>
        /// Localized header text for the username column in the monitor grid.
        /// </summary>
        public string UsernameHeader => LocalizationManager.GetString("UsernameHeader");

        /// <summary> 
        /// Gets or sets the localized placeholder text for the IP address field. 
        /// Displayed when the field is empty and not focused. </summary> 
        public string UsernameWatermarkText
        {
            get => _usernameWatermarkText;
            set
            {
                _usernameWatermarkText = value;

                OnPropertyChanged(nameof(UsernameWatermarkText));
            }
        }

        /// <summary>
        /// Localized text displayed when a public key is valid.
        /// </summary>
        public string ValidPublicKey { get; private set; } = string.Empty;

        /// <summary>
        /// Localized label text for the TCP port number input field.
        /// </summary>
        public string UseTcpPortLabel => LocalizationManager.GetString("UseTcpPortLabel");

        /// <summary>
        /// Gets or sets the brush used for watermark text. The brush is theme‑aware
        /// and updated whenever the theme changes.
        /// </summary>
        public SolidColorBrush WatermarkBrush
        {
            get => _watermarkBrush;
            set
            {
                _watermarkBrush = value;
                OnPropertyChanged(nameof(WatermarkBrush));
            }
        }

        /// <summary>
        /// Represents a dynamic data collection that provides notification
        /// when a user is dded or removed, or when the full list is refreshed.
        /// </summary>
        public ObservableCollection<UserModel> Users { get; set; }

        /// <summary>
        /// Initializes the MainViewModel.
        /// Sets up observable collections, configures the client connection,
        /// initializes the encryption pipeline, and prepares UI‑bound data views.
        /// </summary>
        public MainViewModel()
        {
            // Initializes UI‑bound collections
            Users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<ChatMessage>();

            // Creates client connection with dispatcher callback and reference to this ViewModel.
            // The dispatcher callback ensures that all UI‑affecting actions are marshalled back
            // onto the WPF UI thread.
            // Passing "this" allows the connection layer to push events into the ViewModel.
            _clientConn = new ClientConnection(action => Application.Current.Dispatcher.BeginInvoke(action),
                this);

            // Gets the default view for the Users collection
            // Note: WPF does not sort ObservableCollection automatically, so we obtain
            // the default CollectionView and apply a SortDescription on Username. 
            // This keeps the roster alphabetically ordered in the UI regardless
            // of the order in which connection events arrive from the server.
            var usersView = CollectionViewSource.GetDefaultView(Users);

            // Ensures no previous sort rules remain.
            usersView.SortDescriptions.Clear();

            // Adds ascending sort on Username property.
            usersView.SortDescriptions.Add(new SortDescription(nameof(UserModel.Username),
                ListSortDirection.Ascending));

            // Initializes encryption pipeline with ViewModel and client connection
            EncryptionPipeline = new EncryptionPipeline(this, _clientConn,
                action => Application.Current.Dispatcher.BeginInvoke(action));

            // Notifies UI when AllKeysValid, a calculated property, must refresh after collection changes
            EncryptionPipeline.KnownPublicKeys.CollectionChanged += (_, __) =>
                OnPropertyChanged(nameof(AllKeysValid));

            // Binds connection to pipeline
            _clientConn.EncryptionPipeline = EncryptionPipeline;

            // Subscribes to key‑state changes for lock synchronization
            EncryptionPipeline.KnownPublicKeys.CollectionChanged += OnKnownPublicKeysChanged;

            // Reloads user-scoped settings from disk to ensure the ViewModel
            // starts with the most recently saved values.
            Settings.Default.Reload();
            CurrentIPDisplay = Settings.Default.ServerIPAddress;

            // Restores the saved hue for outgoing bubble color, or applies the default value
            if (double.TryParse(Settings.Default.SentBubbleHue.ToString(), out double savedHue))
            {
                _sentBubbleHue = savedHue;
            }

            else
            {
                _sentBubbleHue = 185.0; // Default hue (light blue)
            }

            // Subscribes to language changes to refresh UI text 
            Properties.Settings.Default.PropertyChanged += OnSettingsPropertyChanged;

            // Creates Connect/Disconnect RelayCommand 
            ConnectDisconnectCommand = new RelayCommand(
                () => { _ = ConnectDisconnectAsync(); },
                () => true
            );

            // Creates ThemeToggleCommand (bound to ToggleButton)
            ThemeToggleCommand = new RelayCommand<object>(param =>
            {
                // Reads toggle state from UI; true = dark, false = light
                bool isDarkThemeSelected = param is bool toggleState && toggleState;

                // Pattern matching (introduced in C# 7):
                // checks type and extracts bool in one step.
                // toggleState only exists inside the expression.
                // Command must rely on UI param, not stored settings.

                Settings.Default.AppTheme = isDarkThemeSelected ? "dark" : "light";
                Settings.Default.Save();

                // Applies theme immediately
                ThemeManager.ApplyTheme(isDarkThemeSelected);
            });

            // Creates request missing public key command (bound to the corresponding button in the monitor)
            RequestMissingPublicKeyCommand =
                new RelayCommand<Guid>(async uid => await RequestMissingPublicKeyAsync(uid));

            LoadLocalizedStrings();

            // Applies tray menu localization
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                mainWindow.ApplyTrayMenuLocalization();
            }

            // Applies saved display font size
            DisplayFontSize = Properties.Settings.Default.DisplayFontSize;
        }

        /// <summary>
        /// Converts a hue value (0–360°) into an RGB color using fixed
        /// saturation and lightness values. This produces a visually
        /// consistent color palette for outgoing message bubbles.
        /// </summary>
        private Color ColorFromHue(double hueDegrees)
        {
            // Normalizes hue to the [0, 360) range
            double normalizedHue = hueDegrees % 360;
            if (normalizedHue < 0)
            {
                normalizedHue += 360;
            }

            // Fixed saturation and lightness
            const double saturation = 0.65;
            const double lightness = 0.70;

            // Computes color intensity
            double colorIntensity = (1 - Math.Abs(2 * lightness - 1)) * saturation;

            // Determines which of the six 60° hue sectors we are in
            double hueSector = normalizedHue / 60.0;

            // Stores the second strongest RGB component for this hue sector
            double secondaryComponent = colorIntensity * (1 - Math.Abs(hueSector % 2 - 1));

            double redComponent = 0.0;
            double greenComponent = 0.0;
            double blueComponent = 0.0;

            // Assigns RGB components based on the hue sector
            if (hueSector < 1)
            {
                redComponent = colorIntensity;
                greenComponent = secondaryComponent;
            }
            else if (hueSector < 2)
            {
                redComponent = secondaryComponent;
                greenComponent = colorIntensity;
            }
            else if (hueSector < 3)
            {
                greenComponent = colorIntensity;
                blueComponent = secondaryComponent;
            }
            else if (hueSector < 4)
            {
                greenComponent = secondaryComponent;
                blueComponent = colorIntensity;
            }
            else if (hueSector < 5)
            {
                redComponent = secondaryComponent;
                blueComponent = colorIntensity;
            }
            else
            {
                redComponent = colorIntensity;
                blueComponent = secondaryComponent;
            }
            
            // Adds the lightness offset to shift RGB components from the [0, chroma] range
            // into the final [0, 1] range required for proper RGB values.
            double lightnessOffset = lightness - colorIntensity / 2.0;

            return Color.FromRgb(
                (byte)((redComponent + lightnessOffset) * 255),
                (byte)((greenComponent + lightnessOffset) * 255),
                (byte)((blueComponent + lightnessOffset) * 255)
            );
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
        public async Task ConnectToServerAsync(CancellationToken cancellationToken = default)
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
                _userHasClickedOnDisconnect = false;
                _suppressRosterNotifications = true;

                // Performs handshake and retrieves UID and server public key
                var (uid, publicKeyDer) = await _clientConn
                    .ConnectToServerAsync(Username.Trim(), ServerIPAddress, cancellationToken)
                    .ConfigureAwait(false);

                // Guards against handshake failure (empty UID or key)
                if (uid == Guid.Empty || publicKeyDer == null || publicKeyDer.Length == 0)
                {
                    ClientLogger.LogLocalized("ConnectionFailed", ClientLogLevel.Error);
                    _ = Application.Current.Dispatcher.BeginInvoke(() =>
                    {
                        ReinitializeUI();

                        // Updates connection state
                        OnPropertyChanged(nameof(IsConnected));

                        // Updates dependent element
                        OnPropertyChanged(nameof(CurrentIPDisplay));

                    });
                    return;
                }

                // Initializes LocalUser with handshake results
                LocalUser = new UserModel
                {
                    Username = Username.Trim(),
                    UID = uid,
                    PublicKeyDer = publicKeyDer
                };

                ClientLogger.Log($"LocalUser initialized (Username='{LocalUser.Username}', UID={LocalUser.UID})", ClientLogLevel.Debug);
                ClientLogger.Log("Connection established - handshake completed", ClientLogLevel.Info);

                // Notifies UI that connection is now established
                OnPropertyChanged(nameof(IsConnected));

                // Updates UI bindings to reflect connected state.
                _ = Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    _userHasClickedOnDisconnect = false;

                    CurrentIPDisplay = "- " + LocalizationManager.GetString("Connected") + " -";

                    OnPropertyChanged(nameof(CurrentIPDisplay));
                    OnPropertyChanged(nameof(ConnectButtonText));

                    // Deferred focus transfer to the message input field
                    _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                    {
                        if (Application.Current.MainWindow is MainWindow mainWindow)
                        {
                            // Makes sure the message input box becomes the real focus target of the window.
                            // FocusManager sets which control should logically receive focus,
                            // and Keyboard.Focus gives it the actual keyboard focus so the user can type immediately.
                            FocusManager.SetFocusedElement(mainWindow, mainWindow.TxtMessageInputField);
                            Keyboard.Focus(mainWindow.TxtMessageInputField);
                            mainWindow.TxtMessageInputField.CaretIndex = mainWindow.TxtMessageInputField.Text.Length;
                        }
                    }), System.Windows.Threading.DispatcherPriority.ApplicationIdle);
                });


                ClientLogger.Log("Server accepted handshake — plaintext messages permitted", ClientLogLevel.Debug);

                /// <summary>
                /// If the user has pre-enabled encryption,
                /// we have all required conditions to start the encryption pipeline:
                /// • TCP connection established
                /// • Handshake completed
                /// • LocalUser and keypair initialized
                /// • UI fully loaded
                /// This ensures encryption is initialized cleanly and predictably.
                /// </summary>
                if (Settings.Default.UseEncryption)
                {
                    // Ensures UI and logs appear in a natural order.
                    await Task.Delay(500, cancellationToken);

                    // Clears previous key material for a fresh session
                    EncryptionPipeline.KnownPublicKeys.Clear();

                    bool encPipelineInitOk = await EncryptionPipeline.InitializeEncryptionAsync(cancellationToken)
                        .ConfigureAwait(false);

                    ClientLogger.Log($"Initialize of encryption pipeline ={encPipelineInitOk} - handshake done",
                        ClientLogLevel.Debug);
                }

                // Restores focus to message input for immediate typing
                _ = Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        mainWindow.TxtMessageInputField.Focus();
                    }
                });
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("Connection attempt canceled by user.", ClientLogLevel.Info);

                _ = Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    ReinitializeUI();

                    // Updates connection state
                    OnPropertyChanged(nameof(IsConnected));

                    // Updates dependent element
                    OnPropertyChanged(nameof(CurrentIPDisplay));
                });
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Fails to connect or handshake: {ex.Message}", ClientLogLevel.Error);

                _ = Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    MessageBox.Show(LocalizationManager.GetString("ServerUnreachable"),
                        LocalizationManager.GetString("Error"), MessageBoxButton.OK, MessageBoxImage.Error);

                    ReinitializeUI();

                    // Updates connection state
                    OnPropertyChanged(nameof(IsConnected));

                    // Updates dependent element
                    OnPropertyChanged(nameof(CurrentIPDisplay));
                });
            }
        }

        /// <summary>
        /// Gets the localized text for the connect/disconnect button.
        /// </summary>
        public string ConnectButtonText => 
            LocalizationManager.GetString(IsConnected ? "Disconnect" : "Connect");

        /// <summary>
        /// Connects or disconnects the client depending on the current state.
        /// Runs asynchronously so the UI thread stays responsive.
        /// </summary>
        public async Task ConnectDisconnectAsync()
        {
            if (_clientConn.IsConnected)
            {
                _userHasClickedOnDisconnect = true;

                // Sends DisconnectNotify without cancellation
                await _clientConn.SendDisconnectNotifyToServerAsync(CancellationToken.None);

                // Closes the connection
                Disconnect();
                return;
            }

            await ConnectToServerAsync().ConfigureAwait(true);
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
                _suppressRosterNotifications = true;

                /// <summary> Closes the underlying TCP connection via the client connection. </summary>
                if (_clientConn?.IsConnected == true)
                {
                    _ = _clientConn.DisconnectFromServerAsync();
                }

                /// <summary> Clears all user/message data in the view. </summary>
                ReinitializeUI();

                /// <summary> Clears message history for privacy and to avoid stale notifications. </summary>
                Messages.Clear();

                /// <summary> Updates connection state </summary>
                OnPropertyChanged(nameof(IsConnected));

                /// <summary> Restores last used IP address </summary>
                CurrentIPDisplay = Settings.Default.ServerIPAddress;
                OnPropertyChanged(nameof(CurrentIPDisplay));

                /// <summary> Updates dependent UI element </summary>
                OnPropertyChanged(nameof(ConnectButtonText));

                /// <summary> Disables encryption pipeline safely. </summary>
                EncryptionPipeline?.DisableEncryption();

                /// <summary> Resets encryption init flag for clean future sessions. </summary>
                Volatile.Write(ref _encryptionInitOnce, 0);
            }
            catch (Exception ex)
            {
                MessageBox.Show(LocalizationManager.GetString("ErrorWhileDisconnecting") + ex.Message,
                    LocalizationManager.GetString("Error"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Error
                );
            }
        }

        /// <summary>
        /// Applies a full roster snapshot from the server.
        /// Updates the Users list and emits “X has joined” / “Y has left” notifications,
        /// except for the local user or when notifications should be suppressed.
        /// </summary>
        /// <param name="rosterEntries">
        /// Full list of connected users (UserId, Username, PublicKeyDer).
        /// </param>
        public void DisplayRosterSnapshot(IEnumerable<(Guid UserId, string Username, byte[] PublicKeyDer)> lstConnectedUsers)
        {
            // Materializes snapshot (avoid multiple enumeration).
            // Type is List<(Guid UserId, string Username, byte[] PublicKeyDer)>,
            // but 'var' is preferred here since the type is obvious and verbose.
            var incomingUsers = lstConnectedUsers
                .Select(e => (e.UserId, e.Username, e.PublicKeyDer))
                .ToList();

            // Converts the list into a dictionary keyed by UserId
            // so we get constant‑time lookups when computing diffs(joined / left users).
            // Avoids repeated O(n) scans, keeps things clean, faster,
            // and reduces unnecessary LINQ with only a O(1) complexity.”
            var incomingLookup = incomingUsers.ToDictionary(e => e.UserId);

            // --- First snapshot: silent initialization ---
            // No notifications, no diff, just fill in the UI list.
            if (_isFirstRosterSnapshot)
            {
                Users.Clear();

                // Goes through every user in the roster snapshot and adds them
                // to our local Users list.
                // Each entry becomes a UserModel with ID, name, and public key.
                foreach (var usr in incomingUsers)
                {
                    Users.Add(new UserModel
                    {
                        UID = usr.UserId,
                        Username = usr.Username,
                        PublicKeyDer = usr.PublicKeyDer
                    });
                }

                // If encryption is enabled and the pipeline is available
                if (Settings.Default.UseEncryption && _clientConn != null && _clientConn.EncryptionPipeline != null)
                {
                    lock (_clientConn.EncryptionPipeline.KnownPublicKeys)
                    {
                        foreach (var usr in incomingUsers)
                        {
                            // Skips local user; we don't need to store our own public key in the peer map.
                            if (LocalUser != null && usr.UserId == LocalUser.UID)
                            {
                                continue;
                            }


                            if (usr.PublicKeyDer != null && usr.PublicKeyDer.Length > 0)
                            {
                                // Snapshot already contains the peer's key, so we store it.
                                var matchingEntry = _clientConn.EncryptionPipeline.KnownPublicKeys
                                    .FirstOrDefault(e => e.UID == usr.UserId);

                                // Builds a short Base64 excerpt for UI display
                                string computedExcerpt = Convert.ToBase64String(usr.PublicKeyDer);
                                if (computedExcerpt.Length > 20)
                                {
                                    computedExcerpt = computedExcerpt.Substring(0, 20) + "....";
                                }

                                if (matchingEntry != null)
                                {
                                    // Updates existing entry in place
                                    matchingEntry.KeyExcerpt = computedExcerpt;
                                    matchingEntry.Username = usr.Username;
                                }
                                else
                                {
                                    // Inserts new entry
                                    _clientConn.EncryptionPipeline.KnownPublicKeys.Add(
                                        new PublicKeyEntry
                                        {
                                            UID = usr.UserId,
                                            Username = usr.Username,
                                            KeyExcerpt = computedExcerpt,
                                        }
                                    );
                                }

                            }
                            else
                            {
                                // No key provided in snapshot, we explicitly request it.
                                _ = _clientConn.SendRequestToPeerForPublicKeyAsync(usr.UserId, CancellationToken.None);
                            }

                        }
                    }
                }

                // Cache snapshot for next diff
                _previousRosterSnapshot = incomingUsers.Select(e => (e.UserId, e.Username)).ToList();
                _isFirstRosterSnapshot = false;
                _suppressRosterNotifications = false;
                return;
            }

            // --- Joined users collection ---
            // Users present now but not in previous snapshot.
            var joinedUsers = incomingUsers
                .Where(e => !_previousRosterSnapshot.Any(p => p.UserId == e.UserId))
                .ToList();

            // --- Left users collection ---
            // Users missing from the new snapshot.
            var leftUsers = _previousRosterSnapshot
                .Where(p => !incomingLookup.ContainsKey(p.UserId))
                .ToList();

            // --- Encryption: update keys for peers present in this snapshot ---
            // If encryption is enabled, ensures we have keys for all non-local peers.
            if (Settings.Default.UseEncryption && _clientConn != null && _clientConn.EncryptionPipeline != null)
            {
                foreach (var usr in incomingUsers)
                {
                    if (LocalUser != null && usr.UserId == LocalUser.UID)
                    {
                        continue; // skips local user
                    }

                    if (usr.PublicKeyDer != null && usr.PublicKeyDer.Length > 0)
                    {
                        // Looks for an existing PublicKeyEntry for this peer
                        var matchingEntry = _clientConn.EncryptionPipeline.KnownPublicKeys
                            .FirstOrDefault(e => e.UID == usr.UserId);

                        // Builds a short Base64 excerpt for UI display
                        string computedExcerpt = Convert.ToBase64String(usr.PublicKeyDer);
                        if (computedExcerpt.Length > 20)
                            computedExcerpt = computedExcerpt.Substring(0, 20) + "....";

                        if (matchingEntry != null)
                        {
                            // Updates existing entry in place
                            matchingEntry.KeyExcerpt = computedExcerpt;
                            matchingEntry.Username = usr.Username;
                         }
                        else
                        {
                            // Inserts new entry
                            _clientConn.EncryptionPipeline.KnownPublicKeys.Add(
                                new PublicKeyEntry
                                {
                                    UID = usr.UserId,
                                    Username = usr.Username,
                                    KeyExcerpt = computedExcerpt,
                                }
                            );
                        }
                    }
                    else
                    {
                        // No key available for this userId, so we request it explicitly.
                        _ = _clientConn.SendRequestToPeerForPublicKeyAsync(usr.UserId, CancellationToken.None);
                    }
                }
            }
            else
            {
                // Pipeline not available yet: keys will be handled later.
                if (Settings.Default.UseEncryption)
                {
                    ClientLogger.Log(
                        "DisplayRosterSnapshot: encryption enabled but pipeline not available; deferring key injection.",
                        ClientLogLevel.Debug
                    );
                }
            }

            // --- Notifications (joined users) ---
            // Skips local user, manual disconnect, or suppressed notifications.
            foreach (var (userId, username, _) in joinedUsers)
            {
                if (LocalUser != null && userId == LocalUser.UID)
                {
                    continue;                   // Don't notify about ourselves
                }

                if (_userHasClickedOnDisconnect)
                {
                    continue;                   // User manually disconnected
                }

                if (_suppressRosterNotifications)
                {
                    continue;                   // Suppression flag active
                }

                Messages.Add(new ChatMessage
                {
                    Text = $"{username} {LocalizationManager.GetString("HasConnected")}",
                    Sender = username,
                    TimeStamp = DateTime.Now.ToString("HH:mm"),
                    IsSystemMessage = true,
                    IsFromLocalUser = false
                });

            }

            // --- Notifications (left users) ---
            foreach (var (userId, username) in leftUsers)
            {
                if (LocalUser != null && userId == LocalUser.UID)
                {
                    continue;                  // Ignores local user
                }

                if (_userHasClickedOnDisconnect)
                {
                    continue;                  // Manual disconnect
                }
                if (_suppressRosterNotifications)
                {
                    continue;                  // Suppression flag active
                }

                Messages.Add(new ChatMessage
                {
                    Text = $"{username} {LocalizationManager.GetString("HasDisconnected")}",
                    Sender = username,
                    TimeStamp = DateTime.Now.ToString("HH:mm"),
                    IsFromLocalUser = false,
                    IsSystemMessage = true
                });
            }

            // --- Updates Users list ---
            // Full replace to avoid stale entries
            Users.Clear();
            foreach (var usr in incomingUsers)
                Users.Add(new UserModel
                {
                    UID = usr.UserId,
                    Username = usr.Username,
                    PublicKeyDer = usr.PublicKeyDer
                });

            // --- Saves snapshot ---
            // Cache for next diff cycle.
            _previousRosterSnapshot = incomingUsers.Select(e => (e.UserId, e.Username)).ToList();

            _suppressRosterNotifications = false;
        }

        /// <summary>
        /// Initializes the watermark brush based on the current theme.
        /// Light theme uses dark grey; dark theme uses light grey.
        /// </summary>
        public void InitializeWatermarkBrush()
        {
            var foregroundBrush = Application.Current.Resources["ForegroundBrush"] as SolidColorBrush;

            if (foregroundBrush == null)
            {
                // Fallback: neutral grey
                WatermarkBrush = new SolidColorBrush(Color.FromRgb(128, 128, 128)) { Opacity = 0.45 };
                return;
            }

            var foregroundBrushColor = foregroundBrush.Color;

            bool isDarkTheme = foregroundBrushColor.R > 200 && foregroundBrushColor.G > 200 && foregroundBrushColor.B > 200;

            var watermarkColor = isDarkTheme ? Color.FromRgb(180, 180, 180) : Color.FromRgb(90, 90, 90);

            WatermarkBrush = new SolidColorBrush(watermarkColor) { Opacity = 0.45 };
        }

        /// <summary>
        /// Initializes localized watermark texts used by the input fields.
        /// Called at startup and whenever the application language changes.
        /// </summary>
        public void InitializeWatermarkResources()
        {
            UsernameWatermarkText = LocalizationManager.GetString("UsernameWatermark");
            IPAddressWatermarkText = LocalizationManager.GetString("IPAddressWatermark");
            ConnectedWatermarkText = "- " + LocalizationManager.GetString("Connected") + " -";
            MessageInputFieldWatermarkText = LocalizationManager.GetString("MessageInputFieldWatermark");
        }

        /// <summary>
        /// Notifies the UI that all localized ViewModel properties must refresh
        /// after a culture change.
        /// </summary>
        public void LoadLocalizedStrings()
        {
            // Tooltips
            OnPropertyChanged(nameof(GettingMissingKeysToolTip));
            OnPropertyChanged(nameof(EncryptionEnabledToolTip));
            OnPropertyChanged(nameof(ScrollLeftToolTip));
            OnPropertyChanged(nameof(ScrollRightToolTip));
            OnPropertyChanged(nameof(SettingsToolTip));

            // Settings window labels and title
            SettingsWindowTitle = LocalizationManager.GetString("SettingsWindowTitle");
            OnPropertyChanged(nameof(UseTcpPortLabel));
            OnPropertyChanged(nameof(ReduceToTrayLabel));
            OnPropertyChanged(nameof(UseEncryptionLabel));
            OnPropertyChanged(nameof(RawTextModeLabel));
            OnPropertyChanged(nameof(DisplayFontSizeLabel));
            OnPropertyChanged(nameof(OutgoingBubbleColorLabel));
            OnPropertyChanged(nameof(MessageInputFieldWidthLabel));
            OnPropertyChanged(nameof(MessageInputFieldLeftOffsetLabel));
            OnPropertyChanged(nameof(AppLanguageLabel));
            OnPropertyChanged(nameof(AboutThisSoftwareLabel));

            // Main window localized properties
            OnPropertyChanged(nameof(ConnectButtonText));
            OnPropertyChanged(nameof(CurrentIPDisplay));

            // Monitor window title and key status texts
            MonitorWindowTitle = LocalizationManager.GetString("MonitorWindowTitle");
            ValidPublicKey = LocalizationManager.GetString("ValidPublicKey");
            MissingOrInvalidPublicKey = LocalizationManager.GetString("MissingOrInvalidPublicKey");
            OnPropertyChanged(nameof(MaskMessage));

            // Monitor DataGrid column headers
            OnPropertyChanged(nameof(UsernameHeader));
            OnPropertyChanged(nameof(KeyExcerptHeader));
            OnPropertyChanged(nameof(StatusHeader));
            OnPropertyChanged(nameof(ActionHeader));

            // Watermark texts
            InitializeWatermarkBrush();

            // Notifies any subscribers that the language has changed
            LanguageChanged?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// Handles a server-initiated disconnect.
        /// Resets UI state, updates bindings and logs a user-visible notification.
        /// </summary>
        public void OnDisconnectedByServer()
        {
            // Hides the display of roster notifications
            _suppressRosterNotifications = true;

            // Indicates if the disconnection is voluntary.
            _userHasClickedOnDisconnect = false;

            // Resets UI state (clears users, messages, input, etc)
            ReinitializeUI();

            // Notifies bindings that the connection state has changed
            OnPropertyChanged(nameof(IsConnected));

            // Restores last known IP address
            CurrentIPDisplay = Settings.Default.ServerIPAddress;
            OnPropertyChanged(nameof(CurrentIPDisplay));

            // Updates connect button text
            OnPropertyChanged(nameof(ConnectButtonText));

            // Disables encryption pipeline
            EncryptionPipeline?.DisableEncryption();
            Volatile.Write(ref _encryptionInitOnce, 0);

            // Clears history also for server-side disconnect
            Messages.Clear();

            // Adds a user-visible notification in the history
            Messages.Add(new ChatMessage
            {
                Text = $"{LocalizationManager.GetString("DisconnectedByServer")}",
                Sender = "System",
                TimeStamp = DateTime.Now.ToString("HH:mm"),
                IsFromLocalUser = false,
                IsSystemMessage = true
            });
        }

        /// <summary>
        /// Handles an incoming encrypted message from the network.
        /// Always validates ciphertext, resolves the sender's display name,
        /// and applies the correct behavior depending on the client's encryption state:
        /// - If encryption is OFF, displays a localized warning instead of attempting decryption.
        /// - If a private key is available, attempts RSA decryption and posts the plaintext to the UI.
        /// - If decryption fails, logs the error and displays a fallback placeholder.
        /// - If no private key exists, displays the raw ciphertext as a last-resort fallback.
        /// All UI updates are dispatched to the main thread.
        /// </summary>

        public void OnEncryptedMessageReceived(Guid senderUid, byte[] cipherBytes)
        {
            if (cipherBytes == null || cipherBytes.Length == 0)
            {
                return;
            }

            string username = Users.FirstOrDefault(u => u.UID == senderUid)?.Username
                              ?? senderUid.ToString();

            // If encryption is OFF, shows localized warning instead of trying to decrypt
            if (!Settings.Default.UseEncryption)
            {
                Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    Messages.Add(new ChatMessage
                    {
                        Text = LocalizationManager.GetString("EnableEncryptionToKeepReadingMessages"),
                        Sender = "System",
                        TimeStamp = DateTime.Now.ToString("HH:mm"),
                        IsFromLocalUser = false,
                        IsSystemMessage = true
                    });
                });
            }

            // If private key exists, tries decrypt
            if (LocalUser?.PrivateKeyDer?.Length > 0)
            {
                try
                {
                    string plaintext = EncryptionHelper.DecryptMessageFromBytes(cipherBytes, LocalUser.PrivateKeyDer);

                    Application.Current.Dispatcher.BeginInvoke(() =>
                    {
                        // Displays the decrypted message with sender's username
                        Messages.Add(new ChatMessage
                        {
                            Text = plaintext,
                            Sender = username,
                            TimeStamp = DateTime.Now.ToString("HH:mm"),
                            IsFromLocalUser = false,
                            IsSystemMessage = false
                        });
                    });
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"Decrypt failed for {senderUid}: {ex.Message}", ClientLogLevel.Error);

                    Application.Current.Dispatcher.BeginInvoke(() =>
                    {
                        Messages.Add(new ChatMessage
                        {
                            Text = $"[decryption failed — {cipherBytes.Length} bytes]",
                            Sender = username,
                            TimeStamp = DateTime.Now.ToString("HH:mm"),
                            IsFromLocalUser = false,
                            IsSystemMessage = true
                        });
                    });
                }
            }
            else
            {
                ClientLogger.Log("Private key missing; showing raw ciphertext.", ClientLogLevel.Warn);

                Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    Messages.Add(new ChatMessage
                    {
                        Text = Encoding.UTF8.GetString(cipherBytes),
                        Sender = username,
                        TimeStamp = DateTime.Now.ToString("HH:mm"),
                        IsFromLocalUser = false,
                        IsSystemMessage = false
                    });
                });
            }
        }

        /// <summary>
        /// Called when the KnownPublicKeys collection changes.
        /// Subscribes to PropertyChanged on added entries, unsubscribes from removed ones,
        /// and re-evaluates the global key‑validity state.
        /// </summary>
        private void OnKnownPublicKeysChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            // Subscribes to new entries
            if (e.NewItems != null)
            {
                foreach (PublicKeyEntry publicKeyEntry in e.NewItems)
                {
                    publicKeyEntry.PropertyChanged += OnPublicKeyEntryChanged;
                }
            }

            // Unsubscribes from removed entries
            if (e.OldItems != null)
            {
                foreach (PublicKeyEntry publicKeyEntry in e.OldItems)
                {
                    publicKeyEntry.PropertyChanged -= OnPublicKeyEntryChanged;
                }
            }

            // Recomputes validity and notify UI if needed
            UpdateLockAnimationState();
        }

        /// <summary>
        /// Handles an incoming plain‑text message by creating a corresponding
        /// ChatMessage instance and appending it to the chat history.
        /// The update is marshaled onto the UI thread to ensure thread‑safe
        /// interaction with observable collections.
        /// This method also determines whether the message originates from the
        /// local user. This distinction is essential because the UI applies
        /// different visual templates (alignment, bubble color, and layout)
        /// depending on whether the message was sent by the user or received
        /// from a peer.
        /// </summary>
        /// <param name="senderName">The display name of the message sender.</param>
        /// <param name="messageToDisplay">The content of the received message.</param>
        public void OnPlainMessageReceived(string senderName, string messageToDisplay)
        {
            try
            {
                Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    Messages.Add(new ChatMessage
                    {
                        Text = messageToDisplay,
                        Sender = senderName,
                        TimeStamp = DateTime.Now.ToString("HH:mm"),

                        // Distinguishing local vs. remote messages is essential:
                        // the UI uses this flag to select the correct bubble template
                        // (right-aligned + colored for local user, left-aligned + white for peer).
                        IsFromLocalUser = string.Equals(senderName, Username, StringComparison.OrdinalIgnoreCase),

                        IsSystemMessage = false
                    });
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
        /// Handles changes inside a PublicKeyEntry (e.g., IsValid).
        /// Triggers a lock‑state refresh when a key's validity changes.
        /// </summary>
        private void OnPublicKeyEntryChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(PublicKeyEntry.IsValid)) 
            { 
                UpdateLockAnimationState();
            }
        }

        /// <summary>
        /// Processes a public key sent by another user and keeps the
        /// known‑keys list accurate and up to date.
        /// • Updates or creates the corresponding PublicKeyEntry  
        /// • Checks whether all peers now have valid keys  
        /// • Triggers an encryption‑readiness evaluation when safe
        /// </summary>

        public void OnPublicKeyReceived(Guid senderUid, byte[]? publicKeyDer)
        {
            // Pipeline must be initialized to process keys.
            if (EncryptionPipeline == null)
            {
                ClientLogger.Log("OnPublicKeyReceived: pipeline not initialized yet; ignoring key.",
                    ClientLogLevel.Debug);
                return;
            }

            // If the received key is null or empty, then we use an empty array.
            // Otherwise, we use the key as it is. This avoids storing a null public key.
            var publicKey = (publicKeyDer == null || publicKeyDer.Length == 0)
                ? Array.Empty<byte>()
                : publicKeyDer;

            bool keyDictionaryUpdated = false;

            // Looks for an existing PublicKeyEntry for this peer.
            var matchingEntry = EncryptionPipeline.KnownPublicKeys
                .FirstOrDefault(e => e.UID == senderUid);

            // Builds a short Base64 excerpt for UI display
            string computedExcerpt = Convert.ToBase64String(publicKey);
            if (computedExcerpt.Length > 20)
                computedExcerpt = computedExcerpt.Substring(0, 20) + "....";

            if (matchingEntry != null)
            {
                // No-op if identical excerpt (key is already known)
                if (matchingEntry.KeyExcerpt == computedExcerpt)
                {
                    ClientLogger.Log($"Public key already known for {senderUid}.", ClientLogLevel.Debug);
                }
                else
                {
                    // Updates existing entry in place
                    matchingEntry.KeyExcerpt = computedExcerpt;
                    matchingEntry.Username = matchingEntry.Username; // unchanged

                    keyDictionaryUpdated = true;
                    ClientLogger.Log($"Updated public key for {senderUid}.", ClientLogLevel.Info);
                }
            }
            else
            {
                // Inserts new entry
                EncryptionPipeline.KnownPublicKeys.Add(
                    new PublicKeyEntry
                    {
                        UID = senderUid,
                        Username = Users.FirstOrDefault(u => u.UID == senderUid)?.Username ?? "",
                        KeyExcerpt = computedExcerpt,
                    }
                );

                keyDictionaryUpdated = true;
                ClientLogger.Log($"Registered new public key for {senderUid}.", ClientLogLevel.Info);
            }

            // Nothing changed, so nothing to evaluate.
            if (!keyDictionaryUpdated)
            {
                return;
            }

            // Don't evaluate until every peer key is in.
            bool allPeerKeysPresent = Users
                .Where(u => u.UID != LocalUser.UID)
                .All(u =>
                {
                    var entry = EncryptionPipeline.KnownPublicKeys
                        .FirstOrDefault(e => e.UID == u.UID);

                    return entry != null && entry.IsValid;
                });

            if (!allPeerKeysPresent)
            {
                ClientLogger.Log("Skipping encryption evaluation — still missing peer keys.",
                    ClientLogLevel.Debug);
                return;
            }

            // All keys available, safe to evaluate.
            RefreshEncryptionState();

            if (AllKeysValid)
            {
                ClientLogger.Log($"Encryption ready after key update from {senderUid}.",
                    ClientLogLevel.Debug);
            }
            else
            {
                ClientLogger.Log("Key updated but encryption not ready yet.", ClientLogLevel.Debug);
            }
        }

        /// <summary>
        /// Reacts to AppLanguage changes by applying the new culture
        /// and reloading all localized ViewModel strings.
        /// </summary>
        private void OnSettingsPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(Settings.Default.AppLanguageCode))
            {
                LocalizationManager.InitializeLocalization(Settings.Default.AppLanguageCode); 
                LoadLocalizedStrings(); 
                return; 
            }

                if (e.PropertyName == nameof(Settings.Default.UseEncryption))
            {
                OnPropertyChanged(nameof(MaskMessage));
                OnPropertyChanged(nameof(IsMaskVisible));
                OnPropertyChanged(nameof(IsGridVisible));
                return;
            }
        }

        /// <summary>
        /// Handles a server-issued DisconnectNotify event.
        /// Removes the user from the local roster, updates the snapshot used 
        /// for roster diffing, and emits a disconnect notification when appropriate.
        /// </summary>
        /// <param name="disconnectedUserId">UID of the user who disconnected.</param>
        /// <param name="username">Display name of the user who disconnected.</param>
        public void OnUserDisconnected(Guid disconnectedUserId, string username)
        {
            var disconnectedUser = Users.FirstOrDefault(u => u.UID == disconnectedUserId);

            // Uses null‑conditional and null‑coalescing operators to pick the first non‑null, non‑empty value.
            string disconnectedUsername = disconnectedUser?.Username ?? username ?? "(unknown)";

            if (disconnectedUser != null)
            {
                Users.Remove(disconnectedUser);
            }

            _previousRosterSnapshot = Users.Select(u => (u.UID, u.Username)).ToList();

            _suppressRosterNotifications = false;

            if (!_userHasClickedOnDisconnect)
            {
                Messages.Add(new ChatMessage
                {
                    Text = $"{disconnectedUsername} {LocalizationManager.GetString("HasDisconnected")}",
                    Sender = "System",
                    TimeStamp = DateTime.Now.ToString("HH:mm"),
                    IsFromLocalUser = false,
                    IsSystemMessage = true
                });

            }
        }

        /// <summary>
        /// Public helper to trigger encryption readiness re-evaluation from connection layer.
        /// Encapsulates pipeline access and raises property change notifications so the UI updates.
        /// </summary>
        public void RefreshEncryptionState()
        {
            EncryptionPipeline?.EvaluateEncryptionState();

            // Ensures UI bindings refresh for IsEncryptionReady
            OnPropertyChanged(nameof(AllKeysValid));
        }

        /// <summary>
        /// Notifies each LanguageOptions item that the UI culture has changed,
        /// so DisplayName is refreshed without rebuilding the collection.
        /// </summary>
        public void RefreshLanguageOptions()
        {
            foreach (var language in SupportedLanguages)
            {
                language.NotifyCultureChanged();
            }
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

            // Resets connection state
            OnPropertyChanged(nameof(IsConnected));

            // Restores the IP display
            CurrentIPDisplay = Properties.Settings.Default.ServerIPAddress;
            OnPropertyChanged(nameof(CurrentIPDisplay));

            // Updates the connect button text
            OnPropertyChanged(nameof(ConnectButtonText));

            // Disables encryption pipeline
            EncryptionPipeline?.DisableEncryption();
            Volatile.Write(ref _encryptionInitOnce, 0);
        }

        /// <summary>
        /// Sends a targeted request to a specific peer asking for its public key.
        /// The UID is provided directly by the monitor and forwarded to the network layer.
        /// Does nothing if the UID refers to the local user.
        /// </summary>
        private async Task RequestMissingPublicKeyAsync(Guid targetUid)
        {
            // Ignores requests targeting the local user's own UID.
            if (targetUid == LocalUser.UID)
                return;

            try
            {
                await ClientConn
                    .SendRequestToPeerForPublicKeyAsync(targetUid, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"RequestMissingPublicKeyAsync failed for UID {targetUid}: {ex.Message}",
                    ClientLogLevel.Error);
            }
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
                OnPropertyChanged(nameof(UseEncryption));
                return;
            }

            UseEncryption = false;
            OnPropertyChanged(nameof(UseEncryption));
        }

        /// <summary>
        /// Returns the username for the given UID, or the UID string if no match is found.
        /// </summary>
        public string ResolveUsername(Guid uid) 
        { 
            return Users.FirstOrDefault(u => u.UID == uid)?.Username ?? uid.ToString(); 
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
        /// Handles user intent to enable or disable encryption.
        /// - If not connected, this method only stores the
        ///   preference for later execution after a successful handshake.
        /// - If connected, it applies the preference immediately:
        ///     • When enabling: starts the encryption pipeline cleanly.
        ///     • When disabling: tears down the pipeline safely.
        /// This method doesn't initialize encryption before the handshake.
        /// </summary>
        public void ToggleEncryptionState(bool enableEncryption)
        {
            bool previousValue = Settings.Default.UseEncryption;

            // Persists user preference
            Settings.Default.UseEncryption = enableEncryption;
            Settings.Default.Save();
            OnPropertyChanged(nameof(UseEncryption));

            // Determines whether the client is fully ready to apply encryption immediately.
            // This requires:
            // • An active TCP connection
            // • A fully initialized LocalUser
            // • A ready EncryptionPipeline instance
            bool isReadyToApplyEncryption = IsConnected && LocalUser != null && EncryptionPipeline != null;

            if (!isReadyToApplyEncryption)
            {
                ClientLogger.Log(enableEncryption
                        ? "Encryption preference enabled; will initialize after next connection."
                        : "Encryption preference disabled (no active connection).",
                    ClientLogLevel.Info);

                return;
            }

            // Connected: apply the preference immediately
            if (enableEncryption)
            {
                // Clear previous key material before reinitializing
                EncryptionPipeline?.KnownPublicKeys.Clear();

                // Fire-and-forget: run pipeline asynchronously in the background.
                _ = Task.Run(async () =>
                {
                    // await cannot wait for a Task<bool>? it needs a Task<bool> not null
                    // So if EncryptionPipeline is null, we must provide a backup Task<bool> => Task.FromResult(false).
                    bool encPipelineInitOk = await (EncryptionPipeline?.InitializeEncryptionAsync(CancellationToken.None)
                        ?? Task.FromResult(false));

                    if (!encPipelineInitOk)
                    {
                        Settings.Default.UseEncryption = previousValue;
                        Settings.Default.Save();
                        OnPropertyChanged(nameof(UseEncryption));

                        ClientLogger.Log("Encryption pipeline initialization failed; preference rolled back.",
                            ClientLogLevel.Warn);
                    }
                });

                ClientLogger.Log("Encryption enable requested (connected).", ClientLogLevel.Info);
            }
            else
            {
                // Disables encryption immediately
                EncryptionPipeline?.DisableEncryption();

                ClientLogger.Log("Encryption disabled via toggle.", ClientLogLevel.Info);
            }
        }

        /// <summary>
        /// Validates and saves the port number if it's within the allowed range.
        /// </summary>
        public static bool TrySavePort(int chosenPort)
        {
            if (chosenPort >= 1000 && chosenPort <= 65535)
            {
                Settings.Default.PortNumber = chosenPort;
                Settings.Default.Save();
                return true;
            }

            return false;
        }

        /// <summary>
        /// Checks for a change in the global key‑validity state and triggers
        /// the lock animation when transitioning from invalid to valid.
        /// The animation must be triggered via an event or a XAML trigger, never directly in the ViewModel.
        /// The XAML listens to IsEncryptionReady
        /// IsEncryptionReady depends on AllKeysValid
        /// When AllKeysValid changes IsEncryptionReady changes and the animation is triggered.
        /// </summary>
        private void UpdateLockAnimationState()
        {
            bool current = AllKeysValid; 
            
            // Only notifies if the value changed
            if (_previousAllKeysValid != current)
            {
                OnPropertyChanged(nameof(AllKeysValid)); 
            }
            
            _previousAllKeysValid = current;
        }
    }
}
