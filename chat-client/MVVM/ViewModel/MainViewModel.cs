/// <file>MainViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 3rd, 2026</date>

using chat_client.Helpers;
using chat_client.MVVM.Model;
using chat_client.MVVM.View;
using chat_client.Net;
using chat_client.Properties;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;


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
        /// Stores the localized tooltip text shown when encryption is fully
        /// enabled and all required keys are available.
        /// </summary>
        private string _encryptionEnabledToolTip = "";

        /// <summary>
        /// Ensures that encryption initialization runs only once per session.
        /// Used as an interlocked flag: 0 = not initialized, 1 = already initialized.
        /// Reset to 0 during disconnect cleanup to allow fresh initialization.
        /// </summary>
        private int _encryptionInitOnce = 0;

        /// <summary>
        /// Backing field storing the tooltip text shown when encryption keys are missing.
        /// </summary>
        private string _gettingMissingKeysToolTip = "";

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
        /// Indicates whether the next roster snapshot is the very first update
        /// received after connecting. 
        /// Suppresses join/leave notifications on first load.
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

        /// <summary>
        /// Backing field storing the current computed width of the right panel.
        /// Updated whenever the window is resized.
        /// </summary>
        private double _rightGridWidth;


        /// <summary>
        /// Backing field for the server IP address used when the client is disconnected.
        /// This value is bound in TwoWay mode to allow user input and is initialized from application settings.
        /// </summary>
        private string _serverIPAddress = Settings.Default.ServerIPAddress;

        /// <summary>Blocks roster notifications during initialization.</summary>
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
        /// Application UI language code.
        /// Persists user choice, reloads resources, and updates UI labels.
        /// </summary>
        public string AppLanguage
        {
            get => _appLanguage;
            set
            {
                if (_appLanguage == value)
                {
                    return;
                }
                _appLanguage = value;

                // Persists the new language choice
                Properties.Settings.Default.AppLanguageCode = value;
                Properties.Settings.Default.Save();

                OnPropertyChanged(nameof(AppLanguage));  // Notifies UI of AppLanguage change

                // Reloads localization resources and refresh all UI labels
                LocalizationManager.InitializeLocalization(value);

                InitializeWatermarkResources();

                // Refreshes ComboBox items so each DisplayName re‐localizes
                OnPropertyChanged(nameof(SupportedLanguages));
            }
        }

        public static string AppLanguageLabel => LocalizationManager.GetString("AppLanguageLabel");


        /// <summary>
        /// Gets the active client connection used by the ViewModel to manage the
        /// network session and monitor connection state. The underlying field is
        /// initialized right after establishing the TCP session and is guaranteed
        /// to be non-null for the lifetime of the ViewModel.
        /// </summary>
        public ClientConnection ClientConn => _clientConn;

        public static string AboutThisSoftwareLabel => LocalizationManager.GetString("AboutThisSoftwareLabel");
      
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

                // Notifies dependent UI elements
                OnPropertyChanged(nameof(UsernameAndIPAddressInputFieldHeight));
                OnPropertyChanged(nameof(ConnectDisconnectButtonHeight));

                // Persists user preference
                Properties.Settings.Default.DisplayFontSize = clampedFontSizeValue;
                Properties.Settings.Default.Save();
            }
        }

        /// <summary>
        /// Gets the localized font size label text
        /// </summary>
        public static string DisplayFontSizeLabel => LocalizationManager.GetString("DisplayFontSizeLabel");

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

        /// <summary>
        /// Gets or sets the localized tooltip text displayed when encryption
        /// is ready. This value is updated through localization and notifies
        /// the UI whenever it changes.
        /// </summary>
        public string EncryptionEnabledToolTip
        {
            get => _encryptionEnabledToolTip;
            set
            {
                _encryptionEnabledToolTip = value;
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
        /// Gets or sets the localized tooltip text displayed when encryption
        /// keys are missing. This value is updated through localization and
        /// notifies the UI whenever it changes.
        /// </summary>
        public string GettingMissingKeysToolTip
        {
            get => _gettingMissingKeysToolTip;
            set
            {
                _gettingMissingKeysToolTip = value;
                OnPropertyChanged();
            }
        }

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
                OnPropertyChanged();

                // Saves the new theme preference
                Settings.Default.AppTheme = value ? "dark" : "light";
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
        /// Gets the maximum font size allowed for UI text scaling.
        /// </summary>
        public static int MaxDisplayFontSize => 36;

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
        public static string MessageInputFieldLeftOffsetLabel => LocalizationManager.GetString("MessageInputFieldLeftOffsetLabel");

        /// <summary>
        /// Stores the percentage (1–100) of horizontal offset applied to the message
        /// input field within the right panel. The value is persisted in application settings.
        /// </summary>
        public double MessageInputFieldLeftOffsetPercent
        {
            get
            {
                double storedLeftOffsetPercent = Properties.Settings.Default.MessageInputFieldLeftOffsetPercent;

                // Fallback to 0% if invalid
                if (storedLeftOffsetPercent < 0)
                    storedLeftOffsetPercent = 0;

                return Math.Clamp(storedLeftOffsetPercent, 0.0, 100.0);
            }
            set
            {
                double clampedValue = Math.Clamp(value, 0.0, 100.0);

                if (Math.Abs(clampedValue - Properties.Settings.Default.MessageInputFieldLeftOffsetPercent) < 0.01)
                    return;

                Properties.Settings.Default.MessageInputFieldLeftOffsetPercent = clampedValue;
                Properties.Settings.Default.Save();

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

        public static string MessageInputFieldWidthLabel => LocalizationManager.GetString("MessageInputFieldWidthLabel");

        /// <summary>
        /// Stores the percentage (1–100) of the right panel width allocated
        /// to the message input field. The value is clamped to prevent the
        /// input field from collapsing, and is persisted in application settings.
        /// </summary>
        public double MessageInputFieldWidthPercent
        {
            get
            {
                double storedMessageInputFieldWidthPercent = Properties.Settings.Default.MessageInputFieldWidthPercent;

                /// <summary> Fallbacks to 60% if the stored value is invalid or zero </summary>
                if (storedMessageInputFieldWidthPercent <= 0)
                {
                    storedMessageInputFieldWidthPercent = 60.0;
                }

                /// <summary> Clamps the value between 1.0 and 100.0 </summary>
                return Math.Clamp(storedMessageInputFieldWidthPercent, 1.0, 100.0);
            }
            set
            {
                // Clamps between 1% and 100% to ensure the input field remains visible
                double clamped = Math.Clamp(value, 1.0, 100.0);

                if (Math.Abs(clamped - Properties.Settings.Default.MessageInputFieldWidthPercent) < 0.01)
                    return;

                Properties.Settings.Default.MessageInputFieldWidthPercent = clamped;
                Properties.Settings.Default.Save();

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
        /// Represents a dynamic data collections that provides notification
        /// when a message is added or removed, or when the full list is refreshed.
        /// </summary>
        public ObservableCollection<string> Messages { get; set; }

        /// <summary>
        /// Minimum font size allowed for UI text scaling.
        /// </summary>
        public static int MinDisplayFontSize => 12;

        /// <summary>
        /// Notifies the UI that a property value has changed.
        /// </summary>
        /// <param name="propertyName">The name of the changed property.</param>
        public void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

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
        /// Collection of languages for the ComboBox (ISO code + localized name).
        /// </summary>
        public ObservableCollection<LanguageOptions> SupportedLanguages { get; }
            = new ObservableCollection<LanguageOptions>
            {
                new LanguageOptions("en"),
                new LanguageOptions("fr")
            };

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
        public static string ReduceToTrayLabel => LocalizationManager.GetString("ReduceToTrayLabel");

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
        public static string ScrollLeftToolTip => LocalizationManager.GetString("ScrollLeftToolTip");
        public static string ScrollRightToolTip => LocalizationManager.GetString("ScrollRightToolTip");

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

        public static string SettingsToolTip => LocalizationManager.GetString("SettingsToolTip");

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

        public static string TrayOpenLabel => LocalizationManager.GetString("TrayOpenLabel");
        public static string TrayQuitLabel => LocalizationManager.GetString("TrayQuitLabel");

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
                OnPropertyChanged();

                /// <summary> Atomically trigger the pipeline toggle via ViewModel </summary>
                ToggleEncryption(value);
            }
        }

        /// <summary>
        /// Gets the localized use encryption for messages label text
        /// </summary>
        public static string UseEncryptionLabel => LocalizationManager.GetString("UseEncryptionLabel");

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

        public static string UseTcpPortLabel => LocalizationManager.GetString("UseTcpPortLabel");


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
            // Initializes collections bound to the UI
            Users = new ObservableCollection<UserModel>();
            Messages = new ObservableCollection<string>();

            // Creates client connection with dispatcher callback and reference to this ViewModel.
            // The dispatcher callback ensures that all UI‑affecting actions are marshalled back
            // onto the WPF UI thread.
            // Passing "this" allows the connection layer to push events into the ViewModel.
            _clientConn = new ClientConnection(action => Application.Current.Dispatcher.BeginInvoke(action), this);

            // Gets the default view for the Users collection
            // Note: WPF does not sort ObservableCollection automatically, so we obtain
            // the default CollectionView and apply a SortDescription on Username. 
            // This keeps the roster alphabetically ordered in the UI regardless
            // of the order in which connection events arrive from the server.
            var usersView = CollectionViewSource.GetDefaultView(Users);

            // Ensures no previous sort rules remain.
            usersView.SortDescriptions.Clear();

            // Adds ascending sort on Username property.
            usersView.SortDescriptions.Add(new SortDescription(nameof(UserModel.Username), ListSortDirection.Ascending));

            // Creates encryption pipeline with ViewModel and client connection
            EncryptionPipeline = new EncryptionPipeline(this, _clientConn,
                action => Application.Current.Dispatcher.BeginInvoke(action)
            );

            // Relays pipeline PropertyChanged to proxy property for UI binding
            EncryptionPipeline.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(EncryptionPipeline.IsEncryptionReady))
                    OnPropertyChanged(nameof(IsEncryptionReady)); // Relay for UI
            };

            // Binds the connection to the pipeline
            _clientConn.EncryptionPipeline = EncryptionPipeline;

            // Reloads user-scoped settings from disk to ensure the ViewModel
            // starts with the most recently saved values.
            Settings.Default.Reload();
            CurrentIPDisplay = Settings.Default.ServerIPAddress;

            // Subscribes to language changes to refresh UI text 
            Properties.Settings.Default.PropertyChanged += OnSettingsPropertyChanged;

            // Creates Connect/Disconnect RelayCommand 
            ConnectDisconnectCommand = new RelayCommand(
                () => { _ = ConnectDisconnectAsync(); },
                () => true
            );

            // Creates ThemeTogglandCommand, which is bound to the UI toggle button.
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
                /// - if yes, it assigns the param value to a new local variable toggleState (of type bool).
                /// - if not, the expression is false and toggleState is not initialized.
                /// "&& toggleState" ensures "toggleState" is only evaluated if the type check succeeds.
                /// </remarks>

                Settings.Default.AppTheme = isDarkThemeSelected ? "dark" : "light";
                Settings.Default.Save();

                ThemeManager.ApplyTheme(isDarkThemeSelected);
            });

            LoadLocalizedStrings();

            int savedDisplayFontSize = Properties.Settings.Default.DisplayFontSize;

            // Applies the font size (this triggers all layout updates)
            DisplayFontSize = savedDisplayFontSize;
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

                ClientLogger.Log($"LocalUser initialized — Username: {LocalUser.Username}, UID: {LocalUser.UID}", ClientLogLevel.Debug);

                // Updates UI bindings to reflect connected state
                _ = Application.Current.Dispatcher.BeginInvoke(() => 
                { 
                    // Notifies connection state
                    OnPropertyChanged(nameof(IsConnected));

                    // Resets manual-disconnect flag
                    _userHasClickedOnDisconnect = false;

                    // Updates display text
                    CurrentIPDisplay = "- " + LocalizationManager.GetString("Connected") + " -"; 
                    
                    // Notifies dependent UI elements
                    OnPropertyChanged(nameof(CurrentIPDisplay)); 
                    OnPropertyChanged(nameof(ConnectButtonText)); 
                });

                ClientLogger.Log("Client connected — plain messages allowed before handshake.", ClientLogLevel.Debug);

                if (Settings.Default.UseEncryption)
                {
                    try
                    {
                        // Ensures client connection exists first
                        _clientConn ??= new ClientConnection(action => 
                        Application.Current.Dispatcher.BeginInvoke(action), this);

                        // Ensures pipeline exists before usage
                        if (EncryptionPipeline == null)
                        {
                            // Creates encryption pipeline with ViewModel, client connection, and dispatcher 
                            EncryptionPipeline = new EncryptionPipeline(this, _clientConn,
                                action => Application.Current.Dispatcher.BeginInvoke(action)
                            );

                            // Binds connection to pipeline
                            _clientConn.EncryptionPipeline = EncryptionPipeline;

                            ClientLogger.Log("EncryptionPipeline is created before usage.", ClientLogLevel.Debug);
                        }

                        //  Assigns in-memory RSA public key for this session
                        LocalUser.PublicKeyDer = EncryptionHelper.PublicKeyDer;
                        ClientLogger.Log($"LocalUser.PublicKeyDer assigned — length={LocalUser.PublicKeyDer?.Length}", ClientLogLevel.Debug);

                        // Validates LocalUser.PublicKeyDer before use
                        if (LocalUser.PublicKeyDer == null || LocalUser.PublicKeyDer.Length == 0)
                        {
                            throw new InvalidOperationException("Public key not initialized");
                        }

                        // Synchronizes the local public key with ClientConnection
                        _clientConn.LocalPublicKey = LocalUser.PublicKeyDer;

                        // Delegates handshake completion and pipeline readiness
                        _clientConn.MarkHandshakeComplete(LocalUser.UID, LocalUser.PublicKeyDer);
                        ClientLogger.Log("Pipeline marked ready for session.", ClientLogLevel.Debug);

                        // Resets encryption state for this new session
                        EncryptionPipeline.KnownPublicKeys.Clear();
                        EncryptionPipeline.IsEncryptionReady = false;
                        await EncryptionPipeline.SyncKeysAsync(cancellationToken).ConfigureAwait(false);

                        // Initializes local encryption context
                        var encryptionInitOk = await EncryptionPipeline.InitializeEncryptionAsync(cancellationToken).ConfigureAwait(false);
                        ClientLogger.Log($"InitializeEncryptionAsync completed — SyncOk={encryptionInitOk}", ClientLogLevel.Debug);

                        // Evaluates encryption state and notify UI if needed 
                        var encryptionReady = EncryptionPipeline.EvaluateEncryptionState();
                        ClientLogger.Log($"EvaluateEncryptionState result — Ready={encryptionReady}", ClientLogLevel.Debug);
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"Encryption setup failed: {ex.Message}", ClientLogLevel.Error);
                    }
                }

                // Restores focus to message input for immediate typing
                _ = Application.Current.Dispatcher.BeginInvoke(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                        mainWindow.TxtMessageInputField.Focus();
                });
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("Connection attempt canceled by user.", ClientLogLevel.Info);

                // Resets UI state after cancellation
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

                // Displays error and resets UI to disconnected state
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
        public void DisplayRosterSnapshot(IEnumerable<(Guid UserId, string Username, byte[] PublicKeyDer)> rosterEntries)
        {
            // Materialize snapshot (avoid multiple enumeration)
            var incomingUsers = rosterEntries
                .Select(e => (UserId: e.UserId, Username: e.Username, PublicKeyDer: e.PublicKeyDer))
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
                foreach (var usr in incomingUsers)
                    Users.Add(new UserModel
                    {
                        UID = usr.UserId,
                        Username = usr.Username,
                        PublicKeyDer = usr.PublicKeyDer
                    });

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

            // --- Encryption: update keys for joined users ---
            // If encryption is enabled, ensures we have keys for new peers.
            if (Settings.Default.UseEncryption)
            {
                foreach (var (userId, _, key) in joinedUsers)
                {
                    if (key.Length > 0)
                    {
                        // Key already provided in snapshot, we store it
                        _clientConn!.EncryptionPipeline!.KnownPublicKeys[userId] = key;
                    }
                    else
                    {
                        // No key available for this userId, so we request it explicitly
                        _ = _clientConn!.SendRequestToPeerForPublicKeyAsync(userId, CancellationToken.None);
                    }
                }
            }

            // --- Notifications (joined users) ---
            // Skips local user, manual disconnect, or suppressed notifications.
            foreach (var (userId, username, _) in joinedUsers)
            {
                if (userId == LocalUser.UID) 
                {
                    continue;                   // Don't notify about ourselves
                }

                if (_userHasClickedOnDisconnect)
                {
                    continue;                   // User manually disconnected, no noise
                }

                if (_suppressRosterNotifications)
                {
                    continue;                   // Suppression flag active
                }

                Messages.Add($"# {username} {LocalizationManager.GetString("HasConnected")} #");
            }

            // --- Notifications (left users) ---
            foreach (var (userId, username) in leftUsers)
            {
                if (userId == LocalUser.UID)
                {
                    continue;                  // Ignores local user
                }

                if (_userHasClickedOnDisconnect) 
                { 
                    continue;                  // No noise on manual disconnect
                }
                if (_suppressRosterNotifications) 
                {
                    continue;                  // Suppression flag active
                }

                Messages.Add($"# {username} {LocalizationManager.GetString("HasDisconnected")} #");
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

            // Tray menu
            OnPropertyChanged(nameof(TrayOpenLabel));
            OnPropertyChanged(nameof(TrayQuitLabel));

            // Settings window labels
            OnPropertyChanged(nameof(UseTcpPortLabel));
            OnPropertyChanged(nameof(ReduceToTrayLabel));
            OnPropertyChanged(nameof(UseEncryptionLabel));
            OnPropertyChanged(nameof(DisplayFontSizeLabel));
            OnPropertyChanged(nameof(MessageInputFieldWidthLabel));
            OnPropertyChanged(nameof(MessageInputFieldLeftOffsetLabel));
            OnPropertyChanged(nameof(AppLanguageLabel));
            OnPropertyChanged(nameof(AboutThisSoftwareLabel));

            // Other localized properties
            OnPropertyChanged(nameof(ConnectButtonText));
            OnPropertyChanged(nameof(CurrentIPDisplay));

            InitializeWatermarkBrush();
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
            Messages.Add("# " + LocalizationManager.GetString("DisconnectedByServer") + " #");
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
                    Messages.Add(LocalizationManager.GetString("EnableEncryptionToReadMessages"));
                });
                return;
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
                        Messages.Add($"{username}: {plaintext}");
                    });
                }
                catch (Exception ex)
                {
                    ClientLogger.Log($"Decrypt failed for {senderUid}: {ex.Message}", ClientLogLevel.Error);

                    Application.Current.Dispatcher.BeginInvoke(() =>
                    {
                        Messages.Add($"{username}: [decryption failed — {cipherBytes.Length} bytes]");
                    });
                }
            }
            else
            {
                ClientLogger.Log("Private key missing; showing raw ciphertext.", ClientLogLevel.Warn);

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
            // Normalizes: never store null
            var publicKey = (publicKeyDer == null || publicKeyDer.Length == 0)
                ? Array.Empty<byte>()
                : publicKeyDer;

            // Ignores self-echo
            if (senderUid == LocalUser.UID) 
            { 
                return;
            }

            bool KeyDictionnaryUpdated = false;

            // Updates KnownPublicKeys safely
            lock (EncryptionPipeline.KnownPublicKeys)
            {
                if (EncryptionPipeline.KnownPublicKeys.TryGetValue(senderUid, out var existingValue))
                {
                    // No-op if identical
                    if (existingValue != null && existingValue.Length == publicKey.Length && existingValue.SequenceEqual(publicKey))
                    {
                        ClientLogger.Log($"Public key already known for {senderUid}.", ClientLogLevel.Debug);
                    }
                    else
                    {
                        EncryptionPipeline.KnownPublicKeys[senderUid] = publicKey;
                        KeyDictionnaryUpdated = true;
                        ClientLogger.Log($"Updated public key for {senderUid}.", ClientLogLevel.Info);
                    }
                }
                else
                {
                    EncryptionPipeline.KnownPublicKeys[senderUid] = publicKey;
                    KeyDictionnaryUpdated = true;
                    ClientLogger.Log($"Registered new public key for {senderUid}.", ClientLogLevel.Info);
                }
            }

            // Nothing changed, so nothing to evaluate
            if (!KeyDictionnaryUpdated)
            {
                return;
            }

            // Don't evaluate until every peer key is in.
            // Prevents early pipeline runs when a new user joins without a key.
            bool allKeysPresent;
            lock (EncryptionPipeline.KnownPublicKeys)
            {
                allKeysPresent = Users
                    .Where(u => u.UID != LocalUser.UID)
                    .All(u =>
                        EncryptionPipeline.KnownPublicKeys.ContainsKey(u.UID) &&
                        EncryptionPipeline.KnownPublicKeys[u.UID] != null &&
                        EncryptionPipeline.KnownPublicKeys[u.UID].Length > 0
                    );
            }

            if (!allKeysPresent)
            {
                ClientLogger.Log("Skipping encryption evaluation — still missing peer keys.", ClientLogLevel.Debug);
                return;
            }

            // All keys available → safe to evaluate
            ReevaluateEncryptionStateFromConnection();

            if (EncryptionPipeline.IsEncryptionReady)
                ClientLogger.Log($"Encryption ready after key update from {senderUid}.", ClientLogLevel.Debug);
            else
                ClientLogger.Log("Key updated but encryption not ready yet.", ClientLogLevel.Debug);
        }


        /// <summary>
        /// Reacts to AppLanguage changes by applying the new culture
        /// and reloading all localized ViewModel strings.
        /// </summary>
        private void OnSettingsPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName != nameof(Settings.Default.AppLanguageCode))
            {
                return;
            }

            LocalizationManager.InitializeLocalization(Settings.Default.AppLanguageCode);
            LoadLocalizedStrings();
        }

        /// <summary>
        /// Handles a server-issued DisconnectNotify event.
        /// Removes the user from the local roster, updates the snapshot used 
        /// for roster diffing, and emits a disconnect notification when appropriate.
        /// </summary>
        /// <param name="userId">UID of the user who disconnected.</param>
        /// <param name="username">Display name of the user who disconnected.</param>
        public void OnUserDisconnected(Guid userId, string username)
        {
            var usr = Users.FirstOrDefault(u => u.UID == userId);

            // Uses null‑conditional and null‑coalescing operators to pick the first non‑null, non‑empty value.
            string realName = usr?.Username ?? username ?? "(unknown)";

            if (usr != null)
            {
                Users.Remove(usr);
            }

            _previousRosterSnapshot = Users.Select(u => (u.UID, u.Username)).ToList();

            _suppressRosterNotifications = false;

            if (!_userHasClickedOnDisconnect)
            {
                Messages.Add($"# {realName} {LocalizationManager.GetString("HasDisconnected")} #");
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
                Settings.Default.PortNumber = chosenPort;
                Settings.Default.Save();
                return true;
            }

            return false;
        }

    }
}
