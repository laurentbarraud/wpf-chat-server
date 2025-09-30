/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 30th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.View;
using chat_client.MVVM.ViewModel;
using chat_client.Properties;
using Hardcodet.Wpf.TaskbarNotification;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;


namespace chat_client
{
    /// <summary>
    /// Primary window for the client-side chat interface.
    /// Hosts the visual components bound to MainViewModel, including message input, user list, and emoji panel.
    /// Handles user interactions such as sending messages, connecting to the server, and toggling UI panels.
    /// Delegates core logic to MainViewModel and ensures thread-safe UI updates.
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainViewModel ViewModel { get; set; }
        
        /// <summary>
        /// Indicates whether the client is currently connected to the server.
        /// Uses null-conditional access to safely evaluate connection state. 
        /// </summary>
        public bool IsConnected => ViewModel?._server != null && ViewModel._server.IsConnected;

        /// <summary>
        /// Height of the emoji panel
        /// </summary>
        public static double EmojiPanelHeight => 30;

        /// <summary>
        /// Represents the tray menu item used to reopen the main application window.
        /// Typically bound to the system tray context menu for restoring visibility when minimized.
        /// </summary>
        public MenuItem TrayMenuOpen { get; private set; }
        
        /// <summary>
        /// Represents the tray menu item used to exit the application.
        /// Bound to the system tray context menu to allow clean shutdown from the tray icon.
        /// </summary>
        public MenuItem TrayMenuQuit { get; private set; }

        /// <summary>
        /// Tray icon variables
        /// </summary>
        private TaskbarIcon trayIcon;


        /// <summary>
        /// Stores the timestamp of the last Ctrl key press.
        /// Used for detecting double-press or timing-based shortcuts.
        /// </summary>
        private DateTime lastCtrlPress = DateTime.MinValue;

        /// <summary>
        /// Scoll variables
        /// </summary>
        private DispatcherTimer scrollTimer;
        private int scrollDirection = 0; // -1 = left, 1 = right

        /// <summary>
        /// Indicates whether the window is still initializing.
        /// Prevents toggle event handlers from applying changes during startup.
        /// </summary>
        private bool IsInitializing = true;

        /// <summary>
        /// Initializes the main window for the encrypted chat client:
        ///   • Loads XAML components and resources.
        ///   • Instantiates and binds the MainViewModel.
        ///   • Wires up chat auto‐scroll and dynamic UI updates (connect button & lock icon).
        ///   • Applies initial UI state based on ViewModel properties.
        ///   • Attaches the emoji panel placement callback.
        ///   • Configures the emoji panel scroll timer.
        ///   • Retrieves XAML‐named tray icon and menu items.
        /// </summary>
        public MainWindow()
        {
            // Load all XAML‐defined elements, styles, and resources
            InitializeComponent();

            // Instantiate and bind the view model
            ViewModel = new MainViewModel();
            DataContext = ViewModel;

            // Auto‐scroll chat when new messages arrive
            ViewModel.Messages.CollectionChanged += Messages_CollectionChanged;

            // Dynamic UI updates: connect button text & encryption icon
            ViewModel.PropertyChanged += ViewModel_PropertyChanged;

            // Apply initial button text and lock icon state
            UpdateConnectButtonText();
            UpdateEncryptionStatusIcon(ViewModel.IsEncryptionReady, ViewModel.IsEncryptionSyncing);

            // Setup the emoji panel placement logic
            AttachEmojiPanelCallback();

            // Configure the auto‐scroll timer for the emoji panel
            scrollTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(50)
            };
            scrollTimer.Tick += ScrollTimer_Tick;

            // Assign WPF‐generated named elements to strongly‐typed fields
            trayIcon = (TaskbarIcon)FindName("TrayIcon");
            TrayMenuOpen = (MenuItem)FindName("TrayMenuOpen");
            TrayMenuQuit = (MenuItem)FindName("TrayMenuQuit");
        }

        /// <summary>
        /// Handles PropertyChanged events from the MainViewModel to update UI elements:
        ///   • Updates the connect/disconnect button label on IsConnected changes.
        ///   • Updates the encryption lock icon on IsEncryptionReady or IsEncryptionSyncing changes.
        /// </summary>
        private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            switch (e.PropertyName)
            {
                case nameof(ViewModel.IsConnected):
                    UpdateConnectButtonText();
                    break;

                case nameof(ViewModel.IsEncryptionReady):
                case nameof(ViewModel.IsEncryptionSyncing):
                    UpdateEncryptionStatusIcon(ViewModel.IsEncryptionReady, ViewModel.IsEncryptionSyncing);
                    break;
            }
        }


        /// <summary>
        /// Handles window load events and applies persisted settings.
        /// Restores IP address, applies localization and theme, initializes watermark visuals,
        /// and evaluates encryption readiness if enabled and connected.
        /// Ensures that the UI reflects the correct cryptographic state on startup.
        /// </summary>
        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Restores last used IP address
            TxtIPAddress.Text = chat_client.Properties.Settings.Default.LastIPAddressUsed;

            // Applies localization if language is not English
            string lang = Properties.Settings.Default.AppLanguage;
            if (lang != "en")
            {
                LocalizationManager.Initialize(lang);
                LocalizationManager.UpdateLocalizedUI();
            }

            CmdSettings.ToolTip = LocalizationManager.GetString("Settings");

            // Synchronizes theme toggle with saved preference
            ThemeToggle.IsChecked = Properties.Settings.Default.AppTheme?.ToLower() == "dark";

            // Applies watermark visuals on startup
            ApplyWatermarkImages();

            TxtUsername.Focus();

            IsInitializing = false;
        }

        /// <summary>
        /// Rebuilds the tray icon context menu using the currently selected language.
        /// Ensures all menu items are localized and reattached to the tray icon.
        /// Safe to call only after tray icon has been initialized.
        /// </summary>
        public void ApplyTrayMenuLocalization()
        {
            if (trayIcon == null)
                return;

            trayIcon.ContextMenu = BuildLocalizedTrayMenu();
        }

        /// <summary>
        /// Changes the watermark images
        /// </summary>
        public void ApplyWatermarkImages()
        {
            string lang = Properties.Settings.Default.AppLanguage;   // "fr" or "en"
            string theme = Properties.Settings.Default.AppTheme;     // "light" or "dark"

            if (lang == "fr")
            {
                if (theme == "dark")
                {
                    imgUsernameWatermark.Source = new BitmapImage(new Uri("/Resources/txtUsername_background_fr_dark.png", UriKind.Relative));
                    imgIPAddressWatermark.Source = new BitmapImage(new Uri("/Resources/txtIPAddress_background_fr_dark.png", UriKind.Relative));
                }
                else // light
                {
                    imgUsernameWatermark.Source = new BitmapImage(new Uri("/Resources/txtUsername_background_fr.png", UriKind.Relative));
                    imgIPAddressWatermark.Source = new BitmapImage(new Uri("/Resources/txtIPAddress_background_fr.png", UriKind.Relative));
                }
            }
            else if (lang == "en")
            {
                if (theme == "dark")
                {
                    imgUsernameWatermark.Source = new BitmapImage(new Uri("/Resources/txtUsername_background_en_dark.png", UriKind.Relative));
                    imgIPAddressWatermark.Source = new BitmapImage(new Uri("/Resources/txtIPAddress_background_en_dark.png", UriKind.Relative));
                }
                else // light
                {
                    imgUsernameWatermark.Source = new BitmapImage(new Uri("/Resources/txtUsername_background_en.png", UriKind.Relative));
                    imgIPAddressWatermark.Source = new BitmapImage(new Uri("/Resources/txtIPAddress_background_en.png", UriKind.Relative));
                }
            }
        }

        /// <summary>
        /// Attempts to bind the custom placement callback for the emoji popup.
        /// Falls back silently if the signature isn’t compatible or something else goes wrong.
        /// </summary>
        private void AttachEmojiPanelCallback()
        {
            if (popupEmojiPanel == null)
                return;

            try
            {
                popupEmojiPanel.CustomPopupPlacementCallback = OnCustomPopupPlacement;
            }
            catch (Exception ex)
            {
                ClientLogger.ClientLog($"Could not assign custom popup placement callback: {ex.Message}",
                    ClientLogLevel.Warn);
            }
        }

        private ContextMenu BuildLocalizedTrayMenu()
        {
            var contextMenu = new ContextMenu();

            TrayMenuOpen = new MenuItem
            {
                Header = LocalizationManager.GetString("TrayOpen")
            };
            TrayMenuOpen.Click += TrayMenu_Open_Click;

            TrayMenuQuit = new MenuItem
            {
                Header = LocalizationManager.GetString("TrayQuit")
            };
            TrayMenuQuit.Click += TrayMenu_Quit_Click;

            contextMenu.Items.Add(TrayMenuOpen);
            contextMenu.Items.Add(TrayMenuQuit);

            return contextMenu;
        }

        private void CmdScrollLeft_MouseEnter(object sender, MouseEventArgs e)
        {
            scrollDirection = -1;
            scrollTimer.Start();
        }

        private void CmdScrollLeft_MouseLeave(object sender, MouseEventArgs e)
        {
            scrollTimer.Stop();
        }

        private void CmdScrollRight_MouseEnter(object sender, MouseEventArgs e)
        {
            scrollDirection = 1;
            scrollTimer.Start();
        }

        private void CmdScrollRight_MouseLeave(object sender, MouseEventArgs e)
        {
            scrollTimer.Stop();
        }

        public void CmdConnectDisconnect_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.ConnectDisconnect();
        }

        /// <summary>
        /// Toggles the emoji popup panel and updates the arrow icon based on its state.
        /// </summary>
        private void CmdEmojiPanel_Click(object sender, RoutedEventArgs e)
        {
            // Disable the button immediately to prevent double clicks
            CmdEmojiPanel.IsEnabled = false;
            ImgEmojiPanel.Source = new BitmapImage(new Uri("/Resources/right-arrow-disabled.png", UriKind.Relative));

            if (popupEmojiPanel.IsOpen)
            {
                popupEmojiPanel.IsOpen = false;
            }
            else
            {
                popupEmojiPanel.VerticalOffset = -popupEmojiPanel.ActualHeight;
                popupEmojiPanel.IsOpen = true;
            }
        }

        /// <summary>
        /// Handles the Send button click event.  
        /// Prevents sending if the message is empty or the client is disconnected.  
        /// Attempts to send the current message to the server.  
        /// Clears and refocuses the input box on success.  
        /// Logs an error and adds a localized failure notice to the ViewModel’s Messages on failure.  
        /// </summary>
        private void CmdSend_Click(object sender, RoutedEventArgs e)
        {
            // Prevents sending if the message is empty or the client is disconnected
            var content = MainViewModel.Message;
            var server = ViewModel._server;
            if (string.IsNullOrEmpty(content) || server?.IsConnected != true)
                return;

            // Attempts to send the current message to the server
            bool sendSucceeded = server.SendMessageToServer(content);

            if (sendSucceeded)
            {
                // Clears and refocuses the input box on success
                TxtMessageToSend.Text = "";
                TxtMessageToSend.Focus();
            }
            else
            {
                // Logs an error and adds a localized failure notice to the ViewModel’s Messages
                ClientLogger.ClientLog(
                    $"Failed to send message: {content}",
                    ClientLogLevel.Error);

                ViewModel.Messages.Add(
                    $"# {LocalizationManager.GetString("SendingFailed")} #");
            }
        }

        private void CmdSettings_Click(object sender, RoutedEventArgs e)
        {
            var settingsWindow = new SettingsWindow();
            settingsWindow.Owner = this;
            settingsWindow.Show();
        }

        /// <summary>
        /// Positions the emoji popup directly above the message input field.
        /// </summary>
        /// <param name="popupSize">The size of the popup content.</param>
        /// <param name="_unusedTargetSize">Unused.</param>
        /// <param name="_unusedOffset">Unused.</param>
        /// <returns>A single placement directly above the target.</returns>
        /// Supprime l’avertissement de paramètre inutilisé
        private static CustomPopupPlacement[] OnCustomPopupPlacement(Size popupSize, Size _unusedTargetSize, Point _unusedOffset)
        {
            double posX = 40;
            double posY = -popupSize.Height;
            return new[]
            {
                new CustomPopupPlacement(new Point(posX, posY), PopupPrimaryAxis.Horizontal)
            };
        }

        public void DisposeTrayIcon()
        {
            var trayIcon = (TaskbarIcon)FindResource("TrayIcon");
            if (trayIcon != null)
            {
                trayIcon.Dispose();
            }
        }

        /// <summary>
        /// Inserts the selected emoji into the message input field.
        /// </summary>
        private void EmojiButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Content is TextBlock tb)
            {
                TxtMessageToSend.Text += tb.Text;
                TxtMessageToSend.Focus();
                TxtMessageToSend.CaretIndex = TxtMessageToSend.Text.Length;
            }
        }

        /// <summary>
        /// Initializes the tray icon with its localized context menu and event handlers.
        /// Uses null-safe casting to avoid runtime warnings and ensures the menu is attached only once.
        /// Handles right-click behavior.
        /// </summary>
        public void EnsureTrayIconReady()
        {
            // Safely retrieve the tray icon resource and assign it if valid
            if (TryFindResource("TrayIcon") is TaskbarIcon icon)
            {
                trayIcon = icon;

                // Attach context menu only if not already set
                if (trayIcon.ContextMenu == null)
                {
                    trayIcon.ContextMenu = BuildLocalizedTrayMenu();

                    // Display context menu on right-click
                    trayIcon.TrayRightMouseUp += (s, e) =>
                    {
                        trayIcon.ContextMenu.PlacementTarget = this;
                        trayIcon.ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint;
                        trayIcon.ContextMenu.IsOpen = true;
                    };
                }
            }
        }

        private void MainWindow1_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (Properties.Settings.Default.ReduceToTray)
            {
                e.Cancel = true;
                ReduceToTray();
            }
        }

        /// <summary>
        /// Handles global key press events to trigger tray reduction behavior
        /// and debug console activation.
        /// Supports Escape key, double Ctrl press within one second,
        /// and Ctrl+Alt+D to open the console on demand.
        /// </summary>
        private void MainWindow1_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            // Skips tray logic if feature is disabled
            if (!chat_client.Properties.Settings.Default.ReduceToTray)
                return;

            // Reduces to tray on Escape key
            if (e.Key == Key.Escape)
            {
                ReduceToTray();
                return;
            }

            // Reduces to tray if Ctrl is pressed twice within one second
            if (e.Key == Key.LeftCtrl || e.Key == Key.RightCtrl)
            {
                var now = DateTime.Now;
                if ((now - lastCtrlPress).TotalMilliseconds < 1000)
                {
                    ReduceToTray();
                }
                lastCtrlPress = now;
            }
        }

        private void MainWindow1_StateChanged(object sender, EventArgs e)
        {
            if (Properties.Settings.Default.ReduceToTray && WindowState == WindowState.Minimized)
            {
                ReduceToTray();
            }
        }

        /// <summary>
        /// Auto‐scrolls the chat view when new messages are added to the collection.
        /// </summary>
        /// <param name="sender">
        /// The source collection that raised the event (nullable).
        /// </param>
        /// <param name="e">
        /// Details about which items were added, removed, or moved (never null).
        /// </param>
        private void Messages_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            // Scrolls to the last message when a new one is added
            if (e.Action == NotifyCollectionChangedAction.Add && lstMessagesReceived.Items.Count > 0)
            {
                lstMessagesReceived.ScrollIntoView(lstMessagesReceived.Items[lstMessagesReceived.Items.Count - 1]);
            }
        }

        protected override void OnContentRendered(EventArgs e)
        {
            base.OnContentRendered(e);

            // Forces refresh after full UI load
            UpdateConnectButtonText();
        }

        /// <summary>
        /// Resets the arrow icon to point right when popup is closed
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void PopupEmojiPanel_Closed(object sender, EventArgs e)
        {
            // Re-enables the button and restores the default icon
            CmdEmojiPanel.IsEnabled = true;
            ImgEmojiPanel.Source = new BitmapImage(new Uri("/Resources/right-arrow.png", UriKind.Relative));
        }

        /// <summary>
        /// Reduces the application to the system tray if the "ReduceToTray" setting is enabled.
        /// Ensures the tray icon is initialized and visible, and hides the main window from the taskbar.
        /// Safe to call from multiple triggers (minimize, Escape, Ctrl+Ctrl, closing).
        /// </summary>
        private void ReduceToTray()
        {
            // Check if tray mode is enabled in settings
            if (!chat_client.Properties.Settings.Default.ReduceToTray)
                return;

            // Retrieve tray icon from resources
            var trayIcon = TryFindResource("TrayIcon") as TaskbarIcon;
            if (trayIcon != null)
            {
                trayIcon.Visibility = Visibility.Visible;
            }

            // Hide main window and remove from taskbar
            this.Hide();
            this.ShowInTaskbar = false;
        }

        /// <summary>
        /// Handles continuous scrolling of the emoji panel when arrow buttons are hovered.
        /// <param name="sender">Timer instance firing the event (nullable).</param>
        /// <param name="e">Event arguments (never null).</param>
        private void ScrollTimer_Tick(object? sender, EventArgs e)
        {
            if (scrollDirection == -1)
            {
                // Scroll left
                emojiScrollViewer.ScrollToHorizontalOffset(emojiScrollViewer.HorizontalOffset - 10);
            }
            else if (scrollDirection == 1)
            {
                // Scroll right
                emojiScrollViewer.ScrollToHorizontalOffset(emojiScrollViewer.HorizontalOffset + 10);
            }
        }

        private void ThemeToggle_Checked(object sender, RoutedEventArgs e)
        {
            if (IsInitializing) return;

            // Save user preference
            Properties.Settings.Default.AppTheme = "Dark";
            Properties.Settings.Default.Save();

            // Apply dark theme to this window with fade animation
            ThemeManager.ApplyTheme(true);

            // Apply dark theme watermarks
            ApplyWatermarkImages();
        }

        private void ThemeToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            if (IsInitializing) return;

            // Save user preference
            Properties.Settings.Default.AppTheme = "Light";
            Properties.Settings.Default.Save();

            // Apply light theme to this window with fade animation
            ThemeManager.ApplyTheme(false);

            // Apply light theme watermarks
            ApplyWatermarkImages();
        }

        /// <summary>
        /// Handles the "Open" action from the tray context menu.
        /// Hides the tray icon and restores the main window to its normal state.
        /// Ensures the window is visible and reappears in the taskbar.
        /// </summary>
        public void TrayMenu_Open_Click(object sender, RoutedEventArgs e)
        {
            var trayIcon = (TaskbarIcon)FindResource("TrayIcon");
            if (trayIcon != null)
            {
                trayIcon.Visibility = Visibility.Collapsed;
            }

            this.Show();
            this.WindowState = WindowState.Normal;
            this.ShowInTaskbar = true;
        }


        public void TrayMenu_Quit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void TxtIPAddress_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                // Simulate the click on the cmdConnect button
                CmdConnectDisconnect.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
        }

        private void TxtMessageToSend_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                // Simulate the click on the CmdSend button
                CmdSend.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));

                // Prevents the line break in the textBox
                e.Handled = true;
            }
        }

        private void TxtMessageToSend_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (TxtMessageToSend.Text == "" || ViewModel._server.IsConnected == false)
            {
                CmdSend.IsEnabled = false;
            }
            else
            {
                CmdSend.IsEnabled = true;
            }
        }

        private void TxtUsername_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                // Simulate the click on the cmdConnect button
                CmdConnectDisconnect.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
        }

        /// <summary>
        /// Handles live updates to the username textbox.
        /// Toggles watermark visibility and connection button state based on input.
        /// Clears the error style if previously applied, restoring the default textbox appearance.
        /// </summary>
        private void TxtUsername_TextChanged(object sender, TextChangedEventArgs e)
        {
            bool textBoxIsEmpty = string.IsNullOrWhiteSpace(TxtUsername.Text);

            // Shows watermark when textbox is empty
            imgUsernameWatermark.Visibility = textBoxIsEmpty ? Visibility.Visible : Visibility.Hidden;

            // Enables the connect button only when input is non-empty
            CmdConnectDisconnect.IsEnabled = !textBoxIsEmpty;

            // Removes the error style if it was previously applied
            if (TxtUsername.Style != null)
            {
                TxtUsername.ClearValue(Control.StyleProperty);
            }
        }

        /// <summary>
        /// Handles live updates to the IP address textbox.
        /// Toggles the visibility of the watermark image based on whether the input field is empty.
        /// </summary>
        private void TxtIPAddress_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Checks if the textbox is empty or contains only whitespace
            bool textBoxIsEmpty = string.IsNullOrWhiteSpace(TxtIPAddress.Text);

            // Shows or hides the watermark image depending on input state
            imgIPAddressWatermark.Visibility = textBoxIsEmpty ? Visibility.Visible : Visibility.Hidden;
        }

        /// <summary>
        /// Updates the text label of the connect/disconnect button based on the current connection state.
        /// Displays a localized "Connect" or "Disconnect" string depending on whether the client is connected.
        /// </summary>
        public void UpdateConnectButtonText()
        {
                CmdConnectDisconnect.Content = ViewModel.IsConnected
                ? LocalizationManager.GetString("DisconnectButton")
                : LocalizationManager.GetString("ConnectButton");
        }
        
        /// <summary>
        /// Updates the encryption status icon and tooltip above the message input field in real time.
        /// Hides the icon entirely if encryption is disabled in settings.
        /// Displays a gray lock icon during public-key sending or key synchronization phases.
        /// Updates the tooltip to reflect current state: sending key, syncing, or ready.
        /// Triggers the Ultra Zoom animation and the colored lock icon when encryption becomes fully active.
        /// </summary>
        /// <param name="isReady">True when all peer keys are synchronized and encryption is ready.</param>
        /// <param name="isSyncing">True while key exchange or synchronization is in progress.</param>
        public void UpdateEncryptionStatusIcon(bool isReady, bool isSyncing = false)
        {
            try
            {
                // Acquires the ViewModel; aborts if not available
                if (DataContext is not MainViewModel viewModel)
                    return;

                // Hides icon when encryption is globally disabled
                if (!Settings.Default.UseEncryption)
                {
                    imgEncryptionStatus.Visibility = Visibility.Collapsed;
                    imgEncryptionStatus.Source = null;
                    imgEncryptionStatus.ToolTip = null;
                    ClientLogger.ClientLog(
                        "Encryption disabled — icon hidden.",
                        ClientLogLevel.Info);
                    return;
                }

                // Ensures icon is visible when encryption is enabled
                imgEncryptionStatus.Visibility = Visibility.Visible;

                // Shows gray icon and sets appropriate tooltip during key send or sync
                if (!isReady)
                {
                    // Displays gray lock icon during key exchange or synchronization
                    imgEncryptionStatus.Source = new BitmapImage(
                        new Uri("/Resources/encrypted-disabled.png", UriKind.Relative));

                    // Chooses tooltip text based on whether syncing is in progress
                    string tooltipKey = isSyncing
                        ? "GettingMissingKeys"
                        : "SendingPublicKey";
                    imgEncryptionStatus.ToolTip = LocalizationManager.GetString(tooltipKey);

                    ClientLogger.ClientLog(
                        $"Encryption in progress — gray icon displayed; tooltip: {tooltipKey}.",
                        ClientLogLevel.Debug);
                    return;
                }

                // Displays colored lock icon and triggers Zoom animation when fully ready
                imgEncryptionStatus.Source = new BitmapImage(
                    new Uri("/Resources/encrypted.png", UriKind.Relative));
                imgEncryptionStatus.ToolTip = LocalizationManager.GetString("EncryptionEnabled");

                // Begins the Ultra Zoom animation defined in XAML
                var storyboard = (Storyboard)FindResource("StarWarsLockDrop");
                storyboard.Begin();

                ClientLogger.ClientLog(
                    "Encryption fully active — colored icon displayed with Zoom animation.",
                    ClientLogLevel.Info);
            }
            catch (Exception ex)
            {
                // Logs any unexpected error and hides the icon to prevent UI disruption
                ClientLogger.ClientLog(
                    $"Error in UpdateEncryptionStatusIcon: {ex.Message}",
                    ClientLogLevel.Error);
                imgEncryptionStatus.Visibility = Visibility.Collapsed;
            }
        }
    }
}