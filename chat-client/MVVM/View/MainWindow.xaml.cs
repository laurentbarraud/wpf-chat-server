/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 26th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.View;
using chat_client.MVVM.ViewModel;
using chat_client.Properties;
using Hardcodet.Wpf.TaskbarNotification;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Data;
using System.Runtime.CompilerServices;
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
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        // PRIVATE FIELD

        /// <summary>
        /// Backing field that stores the default height value
        /// </summary>
        private int _emojiPanelHeight = 20;

        /// <summary>
        /// Stores the timestamp of the last Ctrl key press.
        /// Used for detecting double-press or timing-based shortcuts.
        /// </summary>
        private DateTime lastCtrlPress = DateTime.MinValue;

        /// <summary> Used for horizontal scrolling animations (emoji panel auto‑scroll on hover). </summary>
        private readonly DispatcherTimer scrollTimer;

        /// <summary> Current scroll direction: -1 = scroll left, 1 = scroll right, 0 = idle. </summary>
        private int scrollDirection = 0;

        /// <summary> Tray icon variable </summary>
        private TaskbarIcon trayIcon;

        // PUBLIC PROPERTIES

        public MainViewModel viewModel { get; set; }

        public event PropertyChangedEventHandler? PropertyChanged;
        
        /// <summary>
        /// Gets or sets the base height of the emoji panel.
        /// This value defines the default vertical size of the popup
        /// before any dynamic layout adjustments are applied.
        /// </summary>
        public int EmojiPanelHeight 
        { 
            get => _emojiPanelHeight; 
            set 
            { 
                _emojiPanelHeight = value; 
                OnPropertyChanged(); 
            } 
        }

        /// <summary>
        /// Calculated property that indicates whether the client is currently connected to the server.
        /// Uses null-conditional access to safely evaluate connection state. 
        /// </summary>
        public bool IsConnected => viewModel?.ClientConn != null && viewModel.ClientConn.IsConnected;

        /// <summary>
        /// Indicates whether the window is wide enough or maximized,
        /// in which case the emoji UI scales up slightly for long-session comfort.
        /// </summary>
        public bool IsWindowWide => TxtMessageInputField.ActualWidth > 600 || WindowState == WindowState.Maximized;

        public MainViewModel ViewModel => (MainViewModel)DataContext;


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
        /// Initializes the main window by loading UI components, binding the view model,
        /// restoring user preferences, configuring layout synchronization, and applying
        /// localization, theming, and emoji panel behavior.
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();

            /// <summary> Instantiates and binds the view model </summary>
            viewModel = new MainViewModel();
            DataContext = viewModel;

            /// <summary> Auto-scrolls chat when new messages arrive </summary>
            viewModel.Messages.CollectionChanged += Messages_CollectionChanged;

            /// <summary> Configures the auto-scroll timer for the emoji panel </summary>
            scrollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(50) };
            scrollTimer.Tick += ScrollTimer_Tick;

            /// <summary> Assigns WPF-generated named elements to localized keys </summary>
            trayIcon = (TaskbarIcon)FindName("TrayIcon");
            TrayMenuOpen = (MenuItem)FindName("TrayMenuOpen");
            TrayMenuQuit = (MenuItem)FindName("TrayMenuQuit");

            CmdSettings.ToolTip = LocalizationManager.GetString("Settings");
            CmdScrollLeft.ToolTip = LocalizationManager.GetString("ScrollLeftToolTip");
            CmdScrollRight.ToolTip = LocalizationManager.GetString("ScrollRightToolTip");

            /// <summary> Restores last used IP address </summary>
            TxtServerIPAddress.Text = chat_client.Properties.Settings.Default.ServerIPAddress;

            /// <summary> Applies localization </summary>
            string storedLanguageCode = Properties.Settings.Default.AppLanguageCode;
            LocalizationManager.InitializeLocalization(storedLanguageCode);

            /// <summary> Synchronizes theme toggle with saved preference </summary>
            ThemeToggle.IsChecked = Properties.Settings.Default.AppTheme?.ToLower() == "dark";

            // Restore saved roster width
            ColRoster.Width = new GridLength(Properties.Settings.Default.RosterWidth, GridUnitType.Pixel);

            ApplyWatermarks();
            TxtUsername.Focus();
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
        /// Refreshes all watermark texts and visual states after a language or theme change.
        /// This method updates the ViewModel watermark properties and forces the UI to re‑evaluate
        /// its visibility triggers for each watermark TextBlock.
        /// </summary>
        public void ApplyWatermarks()
        {
            if (DataContext is MainViewModel viewModel)
            {
                // Refreshes localized watermark texts
                viewModel.InitializeWatermarkResources();

                // Refreshes watermarks text
                TxtUsernameWatermark.GetBindingExpression(TextBlock.TextProperty)?.UpdateTarget();
                TxtIPAddressWatermark.GetBindingExpression(TextBlock.TextProperty)?.UpdateTarget();
                TxtMessageInputFieldWatermark.GetBindingExpression(TextBlock.TextProperty)?.UpdateTarget();

                // Refreshes visibility triggers 
                TxtUsernameWatermark.GetBindingExpression(TextBlock.VisibilityProperty)?.UpdateTarget();
                TxtIPAddressWatermark.GetBindingExpression(TextBlock.VisibilityProperty)?.UpdateTarget();
                TxtMessageInputFieldWatermark.GetBindingExpression(TextBlock.VisibilityProperty)?.UpdateTarget();

                // Refreshes the "Connected" / IP display text
                if (viewModel.IsConnected)
                {
                    viewModel.CurrentIPDisplay = LocalizationManager.GetString("Connected");
                }
                else
                {
                    viewModel.CurrentIPDisplay = Settings.Default.ServerIPAddress;
                }

                // Notifies UI in all cases
                viewModel.OnPropertyChanged(nameof(viewModel.CurrentIPDisplay));
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
        /// Show the emoji popup panel and hides the arrow button.
        /// </summary>
        private void CmdEmojiPanel_Click(object sender, RoutedEventArgs e)
        {
            popupEmoji.VerticalOffset = -popupEmoji.ActualHeight;
            popupEmoji.IsOpen = true;
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
                viewModel.ClientConn?.IsConnected != true ||
                viewModel.ClientConn?.IsEstablished != true)
            {
                ClientLogger.Log("Send blocked: connection not yet fully established", ClientLogLevel.Debug);
                return;
            }

            try
            {
                string messageToSend = MainViewModel.MessageToSend;

                // Awaits the unified send method; handles encryption internally if enabled.
                bool success = await viewModel.ClientConn.SendMessageAsync(messageToSend, CancellationToken.None);

                if (success)
                {
                    // Clears the input box and refocuses it on success
                    TxtMessageInputField.Text = "";
                    TxtMessageInputField.Focus();
                }
                else
                {
                    // Notifies user of logical failure (e.g., missing keys or encryption error)
                    viewModel.Messages.Add($"# {LocalizationManager.GetString("SendingFailed")} #");
                }
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("Send operation cancelled", ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Send failed: {ex.Message}", ClientLogLevel.Error);
                viewModel.Messages.Add($"# {LocalizationManager.GetString("SendingFailed")} #");
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
            var settings = new SettingsWindow(viewModel)
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
                TxtMessageInputField.Text += tbEmoji.Text;
                TxtMessageInputField.Focus();
                TxtMessageInputField.CaretIndex = TxtMessageInputField.Text.Length;
            }
        }

        private void GrdMain_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            double colRosterWidth = ColRoster.ActualWidth;

            // Clamps to minimum 20 px
            if (colRosterWidth < 20)
            {
                colRosterWidth = 20;
            }
            
            Properties.Settings.Default.RosterWidth = colRosterWidth; 
            Properties.Settings.Default.Save();
        }

        /// <summary>
        /// Handles size changes of the right panel and updates the ViewModel with
        /// its current pixel width.
        /// </summary>
        private void GrdRight_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            viewModel.RightGridWidth = GrdRight.ActualWidth;
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
            {
                return;
            }

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

        /// <summary>
        /// Handles window state changes and minimizes the application to the
        /// system tray when the user has enabled the "Reduce to tray" option.
        /// </summary>
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
            if (e.Action != NotifyCollectionChangedAction.Add)
            {
                return;
            }

            // UI not ready yet (happens on fast reconnect)
            if (lstReceivedMessages.Items.Count == 0)
            {
                return;
            }

            var lastIndexOfMessage = lstReceivedMessages.Items.Count - 1;

            if (lastIndexOfMessage < 0)
            {
                return;
            }

            lstReceivedMessages.ScrollIntoView(lstReceivedMessages.Items[lastIndexOfMessage]);
        }

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
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
            // Checks if tray mode is enabled in settings
            if (!chat_client.Properties.Settings.Default.ReduceToTray)
                return;

            // Retrieves tray icon from resources
            var trayIcon = TryFindResource("TrayIcon") as TaskbarIcon;
            if (trayIcon != null)
            {
                trayIcon.Visibility = Visibility.Visible;
            }

            // Hides main window and remove from taskbar
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
            Properties.Settings.Default.AppTheme = "dark";
            Properties.Settings.Default.Save();

            // Apply dark theme to this window with fade animation
            ThemeManager.ApplyTheme(true);

            // Apply dark theme watermarks
            ApplyWatermarks();
        }

        private void ThemeToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            // Save user preference
            Properties.Settings.Default.AppTheme = "light";
            Properties.Settings.Default.Save();

            // Apply light theme to this window with fade animation
            ThemeManager.ApplyTheme(false);

            // Apply light theme watermarks
            ApplyWatermarks();
        }

        public void TrayIcon_TrayMouseDoubleClick(object sender, RoutedEventArgs e)
        {
            if (Application.Current.MainWindow is MainWindow mw)
                mw.TrayMenu_Open_Click(sender, e);
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

        /// <summary>
        /// Handles keyboard input inside the message textbox.
        /// Enter alone sends the message.
        /// Shift+Enter inserts a newline (native WPF behavior).
        /// Ctrl+Enter and Alt+Enter also insert a newline (manually).
        /// </summary>
        private void TxtMessageInputField_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            bool isEnter = e.Key == Key.Enter || e.Key == Key.Return;

            // Modifier keys (checked individually for reliability)
            bool isShift = Keyboard.IsKeyDown(Key.LeftShift) || Keyboard.IsKeyDown(Key.RightShift);
            bool isCtrl = Keyboard.IsKeyDown(Key.LeftCtrl) || Keyboard.IsKeyDown(Key.RightCtrl);

            // Shift+Enter → lets WPF insert a newline normally
            if (isEnter && isShift)
            {
                return;
            }

            // Ctrl+Enter: manually insert a newline
            if (isEnter && isCtrl)
            {
                if (sender is TextBox textBox)
                {
                    int caretIndex = textBox.CaretIndex;

                    // Inserts a newline at the current caret position
                    textBox.Text = textBox.Text.Insert(caretIndex, Environment.NewLine);

                    // Moves caret after the inserted newline
                    textBox.CaretIndex = caretIndex + Environment.NewLine.Length;

                    // Prevents default Enter behavior
                    e.Handled = true;
                }

                return;
            }

            // Enter alone
            if (isEnter)
            {
                // Prevents newline insertion
                e.Handled = true;

                // Triggers the send message button (equivalent to WinForms PerformClick)
                CmdSend.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
        }

        private void TxtMessageInputField_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            viewModel.MessageInputFieldWidth = TxtMessageInputField.ActualWidth;
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
                if (DataContext is MainViewModel viewModel) 
                {  
                    viewModel.ConnectDisconnectCommand.Execute(null);
                }

                /// <summary> Stops further propagation of the Enter key </summary>
                e.Handled = true;
            }
        }
    }
}