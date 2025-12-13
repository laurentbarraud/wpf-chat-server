/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 13th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.View;
using chat_client.MVVM.ViewModel;
using Hardcodet.Wpf.TaskbarNotification;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Data;
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
        public bool IsConnected => ViewModel?.ClientConn != null && ViewModel.ClientConn.IsConnected;

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
        /// Stores the timestamp of the last Ctrl key press.
        /// Used for detecting double-press or timing-based shortcuts.
        /// </summary>
        private DateTime lastCtrlPress = DateTime.MinValue;

        /// <summary> Minimum and maximum allowed font sizes for UI text scaling. </summary>
        private const int MinFontSize = 12;
        private const int MaxFontSize = 24;

        /// <summary> Used for horizontal scrolling animations (emoji panel auto‑scroll on hover). </summary>
        private DispatcherTimer scrollTimer;

        /// <summary> Current scroll direction: -1 = scroll left, 1 = scroll right, 0 = idle. </summary>
        private int scrollDirection = 0;

        /// <summary> Tray icon variable </summary>
        private TaskbarIcon trayIcon;

        /// <summary>
        /// Initializes the main window :
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
            /// <summary> Loads all XAML‐defined elements, styles, and resources </summary>
            InitializeComponent();

            /// <summary> Instantiate and bind the view model </summary>
            ViewModel = new MainViewModel();
            DataContext = ViewModel;

            /// <summary> Updates ViewModel with window width </summary>
            this.SizeChanged += (s, e) =>
            {
                if (DataContext is MainViewModel vm)
                {
                    vm.WindowWidth = (int)Math.Round(e.NewSize.Width);
                }
            };

            /// <summary> Auto‐scrolls chat when new messages arrive </summary>
            ViewModel.Messages.CollectionChanged += Messages_CollectionChanged;

            /// <summary> Setup the emoji panel placement logic <summary>
            AttachEmojiPanelCallback();

            /// <summary> Configures the auto‐scroll timer for the emoji panel <summary>
            scrollTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(50)
            };
            scrollTimer.Tick += ScrollTimer_Tick;

            /// <summary> Assigns WPF‐generated named elements to localized keys <summary>
            trayIcon = (TaskbarIcon)FindName("TrayIcon");
            TrayMenuOpen = (MenuItem)FindName("TrayMenuOpen");
            TrayMenuQuit = (MenuItem)FindName("TrayMenuQuit");

            CmdSettings.ToolTip = LocalizationManager.GetString("Settings");
            CmdScrollLeft.ToolTip = LocalizationManager.GetString("ScrollLeftToolTip");
            CmdScrollRight.ToolTip = LocalizationManager.GetString("ScrollRightToolTip");
            TxtFontSizeLabel.Text = LocalizationManager.GetString("ConversationsAndConnectedUsersTextSize") ?? string.Empty;
        }

        /// <summary>
        /// Handles window load events and applies persisted settings.
        /// Restores IP address, applies localization and theme, initializes watermark visuals,
        /// and evaluates encryption readiness if enabled and connected.
        /// Ensures that the UI reflects the correct cryptographic state on startup.
        /// </summary>
        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            /// <summary> Restores last used IP address </summary>
            TxtIPAddress.Text = chat_client.Properties.Settings.Default.LastIPAddressUsed;

            /// <summary> Applies localization </summary>
            string languageSet = Properties.Settings.Default.AppLanguage;
            LocalizationManager.Initialize(languageSet);
            LocalizationManager.UpdateLocalizedUI();

            /// <summary> Synchronizes theme toggle with saved preference <summary>
            ThemeToggle.IsChecked = Properties.Settings.Default.AppTheme?.ToLower() == "dark";

            ApplyWatermarkImages();     
            TxtUsername.Focus();
        }

        /// <summary>
        /// Updates the unified font size used across the UI.
        /// </summary>
        /// <remarks>
        /// The actual resizing of UI elements is handled entirely through XAML bindings:
        /// - message history items update via their DataTemplate binding,
        /// - the connected users list width updates via a bound ViewModel property,
        /// - the message input field updates through its FontSize binding.
        /// This method simply updates the ViewModel property that drives all these bindings,
        /// without directly modifying layout heights to avoid conflicts.
        /// </remarks>
        private void ApplyFontSize(int size)
        {
            ViewModel.ConversationsAndConnectedUsersTextSize = size;
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
            string languageCodeToApply = Properties.Settings.Default.AppLanguage;   // "fr" or "en"
            string themeToApply = Properties.Settings.Default.AppTheme;     // "light" or "dark"

            if (languageCodeToApply == "fr")
            {
                if (themeToApply == "dark")
                {
                    imgUsernameWatermark.Source = new BitmapImage(new Uri("/Resources/txtUsername_background_fr_dark.png", UriKind.Relative));
                    imgIPAddressWatermark.Source = new BitmapImage(new Uri("/Resources/txtIPAddress_background_fr_dark.png", UriKind.Relative));
                }
                else // default : light
                {
                    imgUsernameWatermark.Source = new BitmapImage(new Uri("/Resources/txtUsername_background_fr.png", UriKind.Relative));
                    imgIPAddressWatermark.Source = new BitmapImage(new Uri("/Resources/txtIPAddress_background_fr.png", UriKind.Relative));
                }
            }
            // default : english
            else
            {
                if (themeToApply == "dark")
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
            if (popupEmoji == null)
                return;

            try
            {
                popupEmoji.CustomPopupPlacementCallback = OnPopupPlacement;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Could not assign custom popup placement callback: {ex.Message}",
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

        /// <summary>
        /// Decreases the current font size by one step, respecting min/max limits.
        /// </summary>
        private void CmdDecreaseFont_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.FontSizeSetting > MinFontSize)
            {
                ViewModel.FontSizeSetting--;
                ApplyFontSize(ViewModel.FontSizeSetting);
            }
        }

        /// <summary>
        /// Show the emoji popup panel and hides the arrow button.
        /// </summary>
        private void CmdEmojiPanel_Click(object sender, RoutedEventArgs e)
        {
            popupEmoji.VerticalOffset = -popupEmoji.ActualHeight;
            popupEmoji.IsOpen = true;
            ImgEmojiPanel.Visibility = Visibility.Collapsed;
        }

        /// <summary>
        /// Toggles the font size popup: opens it if closed, closes it if already open.
        /// The popup remains anchored to the font size toolbar button.
        /// </summary>
        private void CmdFontSize_Click(object sender, RoutedEventArgs e)
        {
            popupFontSize.IsOpen = !popupFontSize.IsOpen;
        }

        private void CmdIncreaseFont_Click(object sender, RoutedEventArgs e)
        {
            if (ViewModel.FontSizeSetting < MaxFontSize)
            {
                ViewModel.FontSizeSetting++;
                ApplyFontSize(ViewModel.FontSizeSetting);
            }
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

        /// <summary>
        /// Executes when the user clicks the Send button.
        /// Validates connection state and message content, then awaits SendMessageAsync
        /// (which handles plain or encrypted messages transparently).
        /// Each packet is framed with a 4-byte big-endian length header so the server
        /// can correctly parse the incoming data.
        /// </summary>
        private async void CmdSend_Click(object sender, RoutedEventArgs e)
        {
            // Prevents sending if the message is empty, the socket is not connected,
            // or the handshake/establishment is not yet complete.
            if (string.IsNullOrEmpty(MainViewModel.MessageToSend) ||
                ViewModel.ClientConn?.IsConnected != true ||
                ViewModel.ClientConn?.IsEstablished != true)
            {
                ClientLogger.Log("Send blocked: connection not yet fully established", ClientLogLevel.Debug);
                return;
            }

            try
            {
                string messageToSend = MainViewModel.MessageToSend;

                // Awaits the unified send method; handles encryption internally if enabled.
                bool success = await ViewModel.ClientConn.SendMessageAsync(messageToSend, CancellationToken.None);

                if (success)
                {
                    // Clears the input box and refocuses it on success
                    TxtMessageInput.Text = "";
                    TxtMessageInput.Focus();
                }
                else
                {
                    // Notifies user of logical failure (e.g., missing keys or encryption error)
                    ViewModel.Messages.Add($"# {LocalizationManager.GetString("SendingFailed")} #");
                }
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("Send operation cancelled", ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Send failed: {ex.Message}", ClientLogLevel.Error);
                ViewModel.Messages.Add($"# {LocalizationManager.GetString("SendingFailed")} #");
            }
        }
        
        /// <summary>
        /// Toggles the SettingsWindow visibility:
        /// - If an instance is already open, it closes it.
        /// - If no instance is open, it creates and shows a new one bound to the current MainViewModel.
        /// This prevents multiple SettingsWindow instances from being opened simultaneously.
        /// </summary>
        private void CmdSettings_Click(object sender, RoutedEventArgs e)
        {
            var existingSettingsWindow = Application.Current.Windows
                .OfType<SettingsWindow>()
                .FirstOrDefault();

            if (existingSettingsWindow != null)
            {
                existingSettingsWindow.Close();
                return;
            }

            /// <summary>Creates and shows a new SettingsWindow, passing the current MainViewModel via the ViewModel property</summary>
            var settings = new SettingsWindow(ViewModel)
            {
                /// <summary>
                /// Sets the owner of the SettingsWindow to the MainWindow instance.
                /// This ensures the SettingsWindow stays on top of the main window,
                /// and allows modal behavior such as centering and minimizing together.
                /// </summary>
                Owner = this
            };
            settings.Show();
        }

        /// <summary>
        /// Computes the optimal width for the connected users list based on:
        /// - the current font size,
        /// - the average username length,
        /// - and a typographic width estimation (fontSize * 0.60).
        /// </summary>
        private double ComputeUserListWidth(int fontSize)
        {
            // Retrieve all usernames from the ViewModel
            var names = ViewModel.Users.Select(u => u.Username).ToList();

            // Fallback width if no users are connected
            if (names.Count == 0)
                return 200;

            // Compute average username length
            double avgLength = names.Average(n => n.Length);

            // Approximate pixel width per character (Segoe UI / Emoji)
            double charWidth = fontSize * 0.60;

            // Extra padding for margins, icons, and scrollbar
            double padding = 40;

            // Final predicted width
            return (avgLength * charWidth) + padding;
        }


        /// <summary>
        /// Calculates the custom placement of the font‑size popup so that it appears
        /// horizontally centered and directly above its target button.
        /// </summary>
        private CustomPopupPlacement[] OnFontSizePopupPlacement(Size popupSize, Size targetSize, Point offset)
        {
            /// <summary>
            /// Computes horizontal centering: place the popup so that its center
            /// aligns with the center of the target control.
            /// </summary>
            double x = (targetSize.Width - popupSize.Width) / 2;

            /// <summary>
            /// Positions the popup directly above the target control.
            /// A negative Y value moves the popup upward.
            /// </summary >
            double y = -popupSize.Height;

            return new[]
            {
                new CustomPopupPlacement(new Point(x, y), PopupPrimaryAxis.Horizontal)
            };
        }


        /// <summary>
        /// Positions the emoji popup centered horizontally above the message input field.
        /// </summary>
        private CustomPopupPlacement[] OnPopupPlacement(Size popupSize, Size targetSize, Point _)
        {
            // targetSize = size of TxtMessageInput (PlacementTarget)
            double targetWidth = targetSize.Width;

            // Centers the popup over the input field
            double posX = ((targetWidth - popupSize.Width) / 2) + 22;

            // Places the popup above the input field
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
            if (sender is Button btnEmoji && btnEmoji.Content is TextBlock tbEmoji)
            {
                TxtMessageInput.Text += tbEmoji.Text;
                TxtMessageInput.Focus();
                TxtMessageInput.CaretIndex = TxtMessageInput.Text.Length;
            }
        }

        /// <summary>
        /// Initializes the tray icon with its localized context menu and event handlers.
        /// Uses null-safe casting to avoid runtime warnings and ensures the menu is attached only once.
        /// Handles right-click behavior.
        /// </summary>
        public void InitializeTrayIcon()
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

        private void MainWindow1_Closing(object sender, CancelEventArgs e)
        {
            // If “minimize to tray” is enabled, cancel close and hide instead
            if (Properties.Settings.Default.ReduceToTray)
            {
                e.Cancel = true;
                ReduceToTray();
                return;
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
            if (e.Action == NotifyCollectionChangedAction.Add && lstReceivedMessages.Items.Count > 0)
            {
                lstReceivedMessages.ScrollIntoView(lstReceivedMessages.Items[lstReceivedMessages.Items.Count - 1]);
            }
        }

        /// <summary>
        /// Shows back the arrow icon when popup is closed
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void popupEmoji_Closed(object sender, EventArgs e)
        {
            ImgEmojiPanel.Visibility = Visibility.Visible;
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
                emojiScrollViewer.ScrollToHorizontalOffset(emojiScrollViewer.HorizontalOffset - 20);
            }
            else if (scrollDirection == 1)
            {
                // Scroll right
                emojiScrollViewer.ScrollToHorizontalOffset(emojiScrollViewer.HorizontalOffset + 20);
            }
        }

        private void ThemeToggle_Checked(object sender, RoutedEventArgs e)
        {
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

        private void TxtMessageInput_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                // Simulate the click on the CmdSend button
                CmdSend.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));

                // Prevents the line break in the textBox
                e.Handled = true;
            }
        }

        private void TxtMessageInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (TxtMessageInput.Text == "" || ViewModel.ClientConn.IsConnected == false)
            {
                CmdSend.IsEnabled = false;
            }
            else
            {
                CmdSend.IsEnabled = true;
            }
        }

        /// <summary>
        /// Handles the Enter key in the Username field and invokes the
        /// ConnectDisconnectCommand on the ViewModel.
        /// </summary>
        /// <remarks>
        /// The event is marked as handled to prevent WPF from performing
        /// its default processing of the Enter key (such as moving focus
        /// or triggering other key bindings).
        /// </remarks>
        private void TxtUsername_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                if (DataContext is MainViewModel vm &&
                    vm.ConnectDisconnectCommand.CanExecute(null))
                {
                    vm.ConnectDisconnectCommand.Execute(null);
                }

                /// <summary> Stops further propagation of the Enter key </summary>
                e.Handled = true;
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
    }
}