/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 13th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.View;
using chat_client.MVVM.ViewModel;
using chat_client.Net;
using Hardcodet.Wpf.TaskbarNotification;
using System.Collections.Specialized;
using System.Configuration;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace chat_client
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainViewModel ViewModel { get; set; }

        // Indicates whether the client is currently connected to the server.
        // Uses null-conditional access to safely evaluate connection state.
        public bool IsConnected => ViewModel?.Server != null && ViewModel.Server.IsConnected;

        // Stores the timestamp of the last Ctrl key press.
        // Used for detecting double-press or timing-based shortcuts.
        private DateTime lastCtrlPress = DateTime.MinValue;

        // Tray icon variables
        private TaskbarIcon trayIcon;
        private System.Windows.Forms.Timer hoverTimer;

        // Scoll variables
        private DispatcherTimer scrollTimer;
        private int scrollDirection = 0; // -1 = left, 1 = right

        // Popup variables
        private bool isEmojiPanelOpen = false;

        public double EmojiPanelHeight => 30;

        public MenuItem TrayMenuOpen { get; private set; }
        public MenuItem TrayMenuQuit { get; private set; }

        public Server Server => ViewModel?.Server;

        public MainWindow()
        {
            InitializeComponent();

            // ViewModel binding
            ViewModel = new MainViewModel();
            this.DataContext = ViewModel;

            // Subscribes to message collection changes to trigger autoscroll
            ViewModel.Messages.CollectionChanged += Messages_CollectionChanged;

            // Subscribes to the property change.
            // This ensures that the button is updated automatically
            // as soon as IsConnected changes, without having
            // to call it manually in Connect() or cmdConnectDisconnect_Click.
            ViewModel.PropertyChanged += (s, e) =>
            {
                if (e.PropertyName == nameof(ViewModel.IsConnected))
                {
                    UpdateConnectButtonText();
                }
            };

            // Initialize tray icon and context menu only if "ReduceInTray" setting is enabled
            if (chat_client.Properties.Settings.Default.ReduceInTray)
            {
                // Assign localized context menu to tray icon
                InitializeTrayMenu();

                // Attempt to retrieve the tray icon from application resources
                var trayIcon = TryFindResource("TrayIcon") as TaskbarIcon;

                if (trayIcon != null)
                {
                    // Ensure the tray icon is hidden initially until minimized
                    trayIcon.Visibility = Visibility.Collapsed;
                }
            }

            // Initialize the scroll timer used for emoji panel auto-scrolling
            scrollTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(50)
            };
            scrollTimer.Tick += ScrollTimer_Tick;

        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Restores last used IP address
            txtIPAddress.Text = chat_client.Properties.Settings.Default.LastIPAddressUsed;

            string lang = Properties.Settings.Default.AppLanguage;

            // If the language is different from English, we apply the localization
            if (lang != "en")
            {
                LocalizationManager.Initialize(lang);
                LocalizationManager.UpdateLocalizedUI();
            }

            // Synchronizes the toggle button with the current theme
            ThemeToggle.IsChecked = Properties.Settings.Default.AppTheme == "Dark";

            // Synchronizes the encrypted image visibilty with the current setting
            imgEncryptionStatus.Visibility = Properties.Settings.Default.UseEncryption
                ? Visibility.Visible : Visibility.Collapsed;

            // Apply watermarks on startup
            ApplyWatermarkImages();

            txtUsername.Focus();
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

        private void btnScrollLeft_MouseEnter(object sender, MouseEventArgs e)
        {
            scrollDirection = -1;
            scrollTimer.Start();
        }

        private void btnScrollLeft_MouseLeave(object sender, MouseEventArgs e)
        {
            scrollTimer.Stop();
        }

        private void btnScrollRight_MouseEnter(object sender, MouseEventArgs e)
        {
            scrollDirection = 1;
            scrollTimer.Start();
        }

        private void btnScrollRight_MouseLeave(object sender, MouseEventArgs e)
        {
            scrollTimer.Stop();
        }

        public void cmdConnectDisconnect_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.ConnectDisconnect();
        }

        /// <summary>
        /// Toggles the emoji popup panel and updates the arrow icon based on its state.
        /// </summary>
        private void cmdEmojiPanel_Click(object sender, RoutedEventArgs e)
        {
            // Disable the button immediately to prevent double clicks
            cmdEmojiPanel.IsEnabled = false;
            imgEmojiPanel.Source = new BitmapImage(new Uri("/Resources/right-arrow-disabled.png", UriKind.Relative));

            if (popupEmojiPanel.IsOpen)
            {
                popupEmojiPanel.IsOpen = false;
                isEmojiPanelOpen = false;
            }
            else
            {
                popupEmojiPanel.VerticalOffset = -popupEmojiPanel.ActualHeight;
                popupEmojiPanel.IsOpen = true;
                isEmojiPanelOpen = true;
            }
        }

        /// <summary>
        /// Sends a message to the server
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void cmdSend_Click(object sender, RoutedEventArgs e)
        {
            // Prevent sending if message is empty or client is not connected
            if (!string.IsNullOrEmpty(MainViewModel.Message) && ViewModel.Server?.IsConnected == true)
            {
                ViewModel.Server.SendMessageToServer(MainViewModel.Message);
                txtMessageToSend.Text = "";
                txtMessageToSend.Focus();
            }
        }

        private void cmdSettings_Click(object sender, RoutedEventArgs e)
        {
            var settingsWindow = new SettingsWindow();
            settingsWindow.Owner = this;
            settingsWindow.Show();
        }

        /// <summary>
        /// Calculates a custom placement for the emoji popup so that it appears
        /// directly above the target control (in this case, the message input field).
        /// This ensures precise vertical positioning regardless of layout or control size.
        /// </summary>
        /// <param name="popupSize">The measured size of the popup content.</param>
        /// <param name="targetSize">The size of the control the popup is anchored to.</param>
        /// <param name="offset">The default offset.</param>
        /// <returns>A single CustomPopupPlacement that positions the popup above the target.</returns>
        private CustomPopupPlacement[] OnCustomPopupPlacement(Size popupSize, Size targetSize, Point offset)
        {
            // Position the popup just above the input field
            double x = 40; // horizontal offset to the right
            double y = -popupSize.Height; // position above the target

            // Return a single placement option with the calculated position
            return new[]
            {
                new CustomPopupPlacement(new Point(x, y), PopupPrimaryAxis.Horizontal)
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
                txtMessageToSend.Text += tb.Text;
                txtMessageToSend.Focus();
                txtMessageToSend.CaretIndex = txtMessageToSend.Text.Length;
            }
        }


        /// <summary>
        /// Minimizes the application to the system tray and hides it from the taskbar.
        /// Assumes the tray icon is already defined in App.xaml and initialized at startup.
        /// </summary>
        private void HideToTray()
        {
            // Attempt to retrieve the tray icon from application resources
            var trayIcon = TryFindResource("TrayIcon") as TaskbarIcon;

            if (trayIcon != null)
            {
                // Make the tray icon visible in the system tray
                trayIcon.Visibility = Visibility.Visible;
            }
            else
            {
                // Optional: log or handle missing tray icon (should not happen if properly initialized)
                Debug.WriteLine("TrayIcon resource not found. Ensure it is declared in App.xaml.");
            }

            // Hide the main window and remove it from the taskbar
            this.Hide();
            this.ShowInTaskbar = false;
        }

        /// <summary>
        /// Initializes the tray icon's context menu with localized labels.
        /// Attaches mouse hover and leave events for timed shutdown.
        /// Manually displays the context menu on right-click using WPF placement logic.
        /// Stores menu items in public properties for dynamic updates.
        /// </summary>
        private void InitializeTrayMenu()
        {
            // Create a new WPF context menu for the tray icon
            var trayMenu = new ContextMenu();

            // Create and localize the "Open" menu item
            TrayMenuOpen = new MenuItem
            {
                Header = LocalizationManager.GetString("TrayOpen")
            };
            TrayMenuOpen.Click += TrayMenu_Open_Click;

            // Create and localize the "Quit" menu item
            TrayMenuQuit = new MenuItem
            {
                Header = LocalizationManager.GetString("TrayQuit")
            };
            TrayMenuQuit.Click += TrayMenu_Quit_Click;

            // Add both items to the context menu
            trayMenu.Items.Add(TrayMenuOpen);
            trayMenu.Items.Add(TrayMenuQuit);

            // Retrieve the tray icon resource defined in App.xaml
            var trayIcon = (TaskbarIcon)FindResource("TrayIcon");

            if (trayIcon != null)
            {
                // Attach mouse hover and leave events for timed shutdown
                trayIcon.MouseMove += TrayIcon_MouseMove;
                trayIcon.MouseLeave += TrayIcon_MouseLeave;

                // Manually display the context menu on right-click
                trayIcon.TrayRightMouseUp += (s, e) =>
                {
                    trayMenu.PlacementTarget = this;
                    trayMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint;
                    trayMenu.IsOpen = true;
                };
            }
        }


        private void MainWindow1_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (Properties.Settings.Default.ReduceInTray)
            {
                e.Cancel = true;
                HideToTray();
            }
        }
        /// <summary>
        /// Handles global key press events to trigger behavior
        /// when "reduce in tray" mode is enabled via the settings. 
        /// </summary>
        private void MainWindow1_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (!Properties.Settings.Default.ReduceInTray) return;

            // Ensures tray icon is initialized before hiding
            var trayIcon = TryFindResource("TrayIcon") as TaskbarIcon;
            if (trayIcon == null)
            {
                InitializeTrayMenu();
            }

            if (e.Key == Key.Escape)
            {
                HideToTray();
            }
            // If the Ctrl key is pressed twice within one second
            else if (e.Key == Key.LeftCtrl || e.Key == Key.RightCtrl)
            {
                var now = DateTime.Now;
                if ((now - lastCtrlPress).TotalMilliseconds < 1000)
                {
                    HideToTray();
                }
                lastCtrlPress = now;
            }
        }

        private void MainWindow1_StateChanged(object sender, EventArgs e)
        {
            if (Properties.Settings.Default.ReduceInTray && WindowState == WindowState.Minimized)
            {
                HideToTray();
            }
        }

        private void Messages_CollectionChanged(object sender, NotifyCollectionChangedEventArgs e)
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
            cmdEmojiPanel.IsEnabled = true;
            imgEmojiPanel.Source = new BitmapImage(new Uri("/Resources/right-arrow.png", UriKind.Relative));
            isEmojiPanelOpen = false;
        }

        /// <summary>
        /// Displays a temporary banner at the top of the window with a localized message.
        /// Optionally shows an icon. Slides in and fades out automatically after 2 seconds.
        /// </summary>
        /// <param name="resourceKey">The localization key to display in the banner.</param>
        /// <param name="showIcon">Whether to show the encryption icon.</param>
        public void ShowBanner(string resourceKey, bool showIcon = false)
        {
            string localizedText = LocalizationManager.GetString(resourceKey);
            if (string.IsNullOrEmpty(localizedText))
                localizedText = $"[{resourceKey}]";

            popupText.Text = localizedText;

            // Show or hide the icon based on context
            popupIcon.Visibility = showIcon ? Visibility.Visible : Visibility.Collapsed;
            if (showIcon)
            {
                popupIcon.Source = new BitmapImage(new Uri("/Resources/encrypted.png", UriKind.Relative));
            }

            popupBanner.Visibility = Visibility.Visible;

            var showStoryboard = (Storyboard)FindResource("ShowPopupBannerStoryboard");
            var hideStoryboard = (Storyboard)FindResource("HidePopupBannerStoryboard");

            showStoryboard.Begin();
            hideStoryboard.Begin();

            hideStoryboard.Completed += (s, e) =>
            {
                popupBanner.Visibility = Visibility.Collapsed;
            };
        }

        /// <summary>
        /// Handles continuous scrolling of the emoji panel when arrow buttons are hovered.
        /// </summary>
        private void ScrollTimer_Tick(object sender, EventArgs e)
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
        /// Handles the mouse leave event on the tray icon.
        /// Stops and disposes the hover timer to prevent delayed UI actions or tooltip display.
        /// </summary>
        private void TrayIcon_MouseLeave(object sender, EventArgs e)

        {
            if (hoverTimer != null)
            {
                hoverTimer.Stop();
                hoverTimer.Dispose();
                hoverTimer = null;
            }
        }

        /// <summary>
        /// Starts a timer when the mouse hovers over the tray icon.
        /// If the cursor remains over the icon for 2 seconds without interruption,
        /// the timer triggers application shutdown.
        /// Prevents multiple timers from stacking by checking for null.
        /// </summary>
        private void TrayIcon_MouseMove(object sender, EventArgs e)

        {
            if (hoverTimer == null)
            {
                hoverTimer = new System.Windows.Forms.Timer { Interval = 2000 };
                hoverTimer.Tick += (s, args) =>
                {
                    hoverTimer.Stop();
                    hoverTimer.Dispose();
                    hoverTimer = null;
                    Application.Current.Shutdown();
                };
                hoverTimer.Start();
            }
        }

        /// <summary>
        /// Handles the "Open" action from the tray context menu.
        /// Hides the tray icon and restores the main window to its normal state.
        /// Ensures the window is visible and reappears in the taskbar.
        /// </summary>
        private void TrayMenu_Open_Click(object sender, RoutedEventArgs e)
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


        private void TrayIcon_TrayMouseDoubleClick(object sender, RoutedEventArgs e)
        {
            // Simulates clicking "Open" from the tray menu
            TrayMenu_Open_Click(sender, e);
        }


        private void TrayMenu_Quit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        /// <summary>
        /// Triggers encryption setup after connection if conditions are met.
        /// Called from Server.cs after successful connection.
        /// </summary>
        public void TriggerEncryptionIfNeeded()
        {
            if (ViewModel?.LocalUser != null &&
                Properties.Settings.Default.UseEncryption)
            {
                ViewModel.InitializeEncryptionIfEnabled();
            }
        }


        private void txtIPAddress_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                // Simulate the click on the cmdConnect button
                cmdConnectDisconnect.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
        }

        private void txtMessageToSend_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                // Simulate the click on the cmdSend button
                cmdSend.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));

                // Prevents the line break in the textBox
                e.Handled = true;
            }
        }

        private void txtMessageToSend_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (txtMessageToSend.Text == "" || ViewModel._server.IsConnected == false)
            {
                cmdSend.IsEnabled = false;
            }
            else
            {
                cmdSend.IsEnabled = true;
            }
        }

        private void txtUsername_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                // Simulate the click on the cmdConnect button
                cmdConnectDisconnect.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
        }

        private void txtUsername_TextChanged(object sender, TextChangedEventArgs e)
        {
            bool textBoxIsEmpty = string.IsNullOrWhiteSpace(txtUsername.Text);

            imgUsernameWatermark.Visibility = textBoxIsEmpty ? Visibility.Visible : Visibility.Hidden;
            cmdConnectDisconnect.IsEnabled = !textBoxIsEmpty;

            if (txtUsername.Background is SolidColorBrush brush &&
                brush.Color == (Color)ColorConverter.ConvertFromString("#DC143C"))
            {
                // Restores the themed background brush from resources
                var defaultBrush = TryFindResource("BackgroundBrush") as Brush;
                if (defaultBrush != null)
                {
                    txtUsername.Background = defaultBrush;
                }
            }

        }

        private void txtIPAddress_TextChanged(object sender, TextChangedEventArgs e)
        {
            bool textBoxIsEmpty = string.IsNullOrWhiteSpace(txtIPAddress.Text);

            imgIPAddressWatermark.Visibility = textBoxIsEmpty ? Visibility.Visible : Visibility.Hidden;
        }

        /// <summary>
        /// Updates the text label of the connect/disconnect button based on the current connection state.
        /// Displays a localized "Connect" or "Disconnect" string depending on whether the client is connected.
        /// </summary>
        public void UpdateConnectButtonText()
        {
            cmdConnectDisconnect.Content = ViewModel.IsConnected
                ? LocalizationManager.GetString("DisconnectButton")
                : LocalizationManager.GetString("ConnectButton");
        }

        /// <summary>
        /// Updates the encryption status icon and tooltip above the message input field.
        /// Reflects the current encryption state based on key exchange success and application settings.
        /// Displays the colored icon if encryption is active and the public key is present; otherwise shows the default icon.
        /// Ensures visual feedback remains consistent across toggle changes, connection events, and localization.
        /// Designed for modular UI updates without direct dependency on toggle logic or connection flow.
        /// Autonomous, reliable, and seamlessly integrated into the application's lifecycle.
        /// </summary>
        public void UpdateEncryptionStatusIcon()
        {
            var viewModel = DataContext as MainViewModel;
            if (viewModel == null)
                return;

            // Hide the icon if encryption is disabled in settings
            if (!viewModel.IsEncryptionEnabled)
            {
                imgEncryptionStatus.Visibility = Visibility.Collapsed;
                return;
            }

            // Determine whether the public key has been successfully generated and stored
            bool keySent = !string.IsNullOrEmpty(viewModel.LocalUser?.PublicKeyBase64);

            // Show the icon since encryption is enabled
            imgEncryptionStatus.Visibility = Visibility.Visible;

            // Set the icon source depending on key exchange status
            imgEncryptionStatus.Source = new BitmapImage(new Uri(
                keySent
                    ? "/Resources/encrypted.png"
                    : "/Resources/encrypted-disabled.png",
                UriKind.Relative));

            // Set the tooltip using localized string
            imgEncryptionStatus.ToolTip = LocalizationManager.GetString(
                keySent ? "EncryptionEnabled" : "GetPublicKey"
            );

            // Trigger pulse animation and show banner only if key exchange was successful
            if (keySent)
            {
                var storyboard = (Storyboard)FindResource("EncryptionPulseAnimation");
                storyboard.Begin();

                ShowBanner("EncryptionEnabled", showIcon: true);
            }
        }
    }
}