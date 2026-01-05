/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 5th, 2026</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.Properties;
using Hardcodet.Wpf.TaskbarNotification;
using Microsoft.VisualBasic.ApplicationServices;
using Microsoft.VisualBasic.Logging;
using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;


namespace chat_client.MVVM.View
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
        private DateTime _lastCtrlPress = DateTime.MinValue;

        /// <summary>
        /// Holds a reference to the internal ScrollViewer of the chat ListBox,
        /// allowing reliable auto-scrolling when new messages are added.
        /// </summary>
        private ScrollViewer? _messagesScrollViewer;

        /// <summary>  Defines the minimum allowed height for the input area. </summary>
        private const double _MIN_INPUT_AREA_HEIGHT = 34;

        /// <summary>
        /// Indicates whether all persisted layout values (roster width and
        /// input area height) should be restored after the first valid
        /// layout pass of the window.
        /// </summary>
        private bool _pendingInitialRestore = true;

        /// <summary> Current scroll direction: -1 = scroll left, 1 = scroll right, 0 = idle. </summary>
        private int _scrollDirection = 0;

        /// <summary> Used for horizontal scrolling animations (emoji panel auto‑scroll on hover). </summary>
        private readonly DispatcherTimer scrollTimer;

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

        // Initializes the main window: loads UI components, binds the ViewModel,
        // restores user preferences, configures layout synchronization, and applies
        // localization, theming, and emoji panel behavior.
        public MainWindow()
        {
            InitializeComponent();

            // Creates and binds the ViewModel
            viewModel = new MainViewModel(); 
            DataContext = viewModel;

            // Will react to ViewModel layout updates
            viewModel.PropertyChanged += ViewModel_PropertyChanged; 
        
            // Auto-scrolls chat when new messages arrive
            viewModel.Messages.CollectionChanged += Messages_CollectionChanged;

            // Configures the auto-scroll timer for the emoji panel
            scrollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(50) };
            scrollTimer.Tick += ScrollTimer_Tick;

            // Assigns WPF-generated named elements to localized keys
            trayIcon = (TaskbarIcon)FindName("TrayIcon");
            TrayMenuOpen = (MenuItem)FindName("TrayMenuOpen");
            TrayMenuQuit = (MenuItem)FindName("TrayMenuQuit");

            CmdSettings.ToolTip = LocalizationManager.GetString("SettingsToolTip");
            CmdScrollLeft.ToolTip = LocalizationManager.GetString("ScrollLeftToolTip");
            CmdScrollRight.ToolTip = LocalizationManager.GetString("ScrollRightToolTip");

            // Restores last used IP address
            TxtServerIPAddress.Text = Settings.Default.ServerIPAddress;

            // Applies localization
            string storedLanguageCode = Settings.Default.AppLanguageCode;
            LocalizationManager.InitializeLocalization(storedLanguageCode);

            // Synchronizes theme toggle with saved preference
            ThemeToggle.IsChecked = Settings.Default.AppTheme?.ToLower() == "dark";

            // Restores saved message input field height
            double savedHeight = Settings.Default.InputAreaHeight;
            
            if (savedHeight < 34)
            {
                savedHeight = 34;
            }

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
            popupEmoji.Visibility = Visibility.Visible;
            popupEmoji.IsOpen = true;
        }

        private void CmdScrollLeft_MouseEnter(object sender, MouseEventArgs e)
        {
            _scrollDirection = -1;
            scrollTimer.Start();
        }

        private void CmdScrollLeft_MouseLeave(object sender, MouseEventArgs e)
        {
            scrollTimer.Stop();
        }

        private void CmdScrollRight_MouseEnter(object sender, MouseEventArgs e)
        {
            _scrollDirection = 1;
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
            if (string.IsNullOrEmpty(viewModel.MessageToSend) ||
                viewModel.ClientConn?.IsConnected != true ||
                viewModel.ClientConn?.IsEstablished != true)
            {
                ClientLogger.Log("Send blocked: connection not yet fully established", ClientLogLevel.Debug);
                return;
            }

            try
            {
                string messageToSend = viewModel.MessageToSend;

                // Awaits the unified send method; handles encryption internally if enabled.
                bool success = await viewModel.ClientConn.SendMessageAsync(messageToSend, CancellationToken.None);

                if (success)
                {
                    // The TextBox will automatically empty thanks to the binding.
                    viewModel.MessageToSend = "";
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
        /// - CTRL + Click opens AboutWindow directly.
        /// This prevents multiple SettingsWindow instances from being opened simultaneously.
        /// </summary>
        private void CmdSettings_Click(object sender, RoutedEventArgs e)
        {
            // CTRL is hold: opens AboutWindow
            if (Keyboard.Modifiers == ModifierKeys.Control)
            {
                var about = new AboutWindow
                {
                    Owner = this
                };
                about.ShowDialog();
                return;
            }

            // Normal behavior: toggles SettingsWindow
            var existingSettingsWindow = Application.Current.Windows
                .OfType<SettingsWindow>()
                .FirstOrDefault();

            if (existingSettingsWindow != null)
            {
                existingSettingsWindow.Close();
                return;
            }

            var settings = new SettingsWindow(viewModel)
            {
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

        /// <summary>
        /// Tries to find a child element of type T somewhere inside the visual tree.
        /// Gets the ScrollViewer hidden inside the ListBox template.
        /// </summary>
        private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
        {
            // Number of children inside this visual element
            int childCount = VisualTreeHelper.GetChildrenCount(parent);

            // Loops through all direct children
            for (int childIndex = 0; childIndex < childCount; childIndex++)
            {
                // Gets the child at the current index
                DependencyObject currentChild = VisualTreeHelper.GetChild(parent, childIndex);

                // If the child is already the type we want, returns it
                if (currentChild is T typedChild)
                {
                    return typedChild;
                }

                // Otherwise, try to search deeper inside this child
                T? foundChild = FindVisualChild<T>(currentChild);

                // If something was found deeper, returns it
                if (foundChild != null)
                {
                    return foundChild;
                }
            }

            // If nothing was found at all, returns null
            return null;
        }



        private void GrdMain_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            double totalWidth = GrdMain.ActualWidth;

            // Maximum allowed width for the roster
            double maxRosterWidth = totalWidth / 2.0;

            // Current roster width
            double colRosterWidth = ColRoster.ActualWidth;

            // Clamps to minimum 40 px
            if (colRosterWidth < 40)
            {
                colRosterWidth = 40;
            }

            // Clamps to maximum half of the window width
            if (colRosterWidth > maxRosterWidth)
            {
                colRosterWidth = maxRosterWidth;
            }

            // Applies the clamped width
            ColRoster.Width = new GridLength(colRosterWidth, GridUnitType.Pixel);

            // Enforces the hard limit on the left grid
            GrdLeft.MaxWidth = maxRosterWidth;
        }

        /// <summary>
        /// Handles size changes of the right panel and updates the ViewModel with
        /// its current pixel width.
        /// </summary>
        private void GrdRight_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            // Updates the width of the right panel
            viewModel.RightGridWidth = GrdRight.ActualWidth; 
        }

        /// <summary> 
        /// Enforces minimum height constraints for both the messages area and the
        /// bottom input area while the horizontal splitter is being dragged.
        /// Cancels the drag movement when a limit would be exceeded, 
        /// ensuring the layout remains stable and visually usable during resizing.
        /// </summary>
        private void HorizontalSplitter_DragDelta(object sender, DragDeltaEventArgs e)
        {
            double totalHeight = GrdRight.ActualHeight;

            // Mouse position relative to the right panel
            Point mousePos = Mouse.GetPosition(GrdRight);

            // Height the bottom area would have if the splitter moved here
            double newBottomHeight = totalHeight - mousePos.Y;

            const double MinMessagesAreaHeight = 20;
            const double MinBottomHeight = 66;

            // Prevents bottom area from becoming too small
            if (newBottomHeight < MinBottomHeight)
            {
                e.Handled = true;
                return;
            }

            // Prevents messages area from becoming too small
            double newMessagesHeight = totalHeight - newBottomHeight - 5;
            if (newMessagesHeight < MinMessagesAreaHeight)
            {
                e.Handled = true;
            }
        }

        /// <summary> Saves the input area height when the horizontal splitter drag operation completes. </summary> 
        private void HorizontalSplitter_DragCompleted(object sender, DragCompletedEventArgs e) 
        { 
            double actualHeight = GrdBottom.ActualHeight;

            if (actualHeight < _MIN_INPUT_AREA_HEIGHT)
            {
                actualHeight = _MIN_INPUT_AREA_HEIGHT;
            }

            Settings.Default.InputAreaHeight = actualHeight; 
            Settings.Default.Save(); 
        }

        /// <summary>
        /// Applies minimum height constraints while the horizontal splitter is being dragged.
        /// This prevents the messages area or the bottom input area from shrinking below
        /// their allowed limits during live mouse movement.
        /// </summary>
        private void HorizontalSplitter_PreviewMouseMove(object sender, MouseEventArgs e)
        {
            // Only enforces limits while the user is actively dragging the splitter
            if (e.LeftButton != MouseButtonState.Pressed)
            {
                return;
            }

            // Total height of the right panel (messages history + splitter + bottom area)
            double totalHeight = GrdRight.ActualHeight;

            // Mouse position relative to GrdRight
            Point mousePosition = e.GetPosition(GrdRight);

            // If the splitter moved to this Y position, the bottom area would become:
            double newBottomHeight = totalHeight - mousePosition.Y;

            const double MinMessagesAreaHeight = 20;
            const double MinBottomHeight = 66;

            // Prevents bottom area from becoming too small
            if (newBottomHeight < MinBottomHeight)
            {
                e.Handled = true;
                return;
            }

            // Height of the messages area if the splitter moved to this position
            double newMessagesAreaHeight = totalHeight - newBottomHeight - 5;

            // Prevents messages area from becoming too small
            if (newMessagesAreaHeight < MinMessagesAreaHeight)
            {
                e.Handled = true;
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

        /// <summary> 
        /// Captures the internal ScrollViewer of the chat ListBox once the visual tree 
        /// is fully loaded, enabling direct scrolling to the bottom.
        /// </summary>
        private void lstReceivedMessages_Loaded(object sender, RoutedEventArgs e)
        {
            _messagesScrollViewer = FindVisualChild<ScrollViewer>(lstReceivedMessages);
        }
        private void MainWindow_Closing(object sender, CancelEventArgs e)
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
        private void MainWindow_PreviewKeyDown(object sender, KeyEventArgs e)
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
                if ((now - _lastCtrlPress).TotalMilliseconds < 1000)
                {
                    ReduceToTray();
                }
                _lastCtrlPress = now;
            }
        }

        /// <summary>
        /// Handles window state changes and minimizes the application to the
        /// system tray when the user has enabled the "Reduce to tray" option.
        /// </summary>
        private void MainWindow_StateChanged(object sender, EventArgs e)
        {
            if (Properties.Settings.Default.ReduceToTray && WindowState == WindowState.Minimized)
            {
                ReduceToTray();
            }
        }

        /// <summary> 
        /// Automatically scrolls the chat view to the latest message
        /// whenever a new item is added to the collection. 
        /// Uses the internal ScrollViewer to ensure reliable scrolling
        /// even with custom ListBox templates.
        /// </summary>
        private void Messages_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            if (e.Action != NotifyCollectionChangedAction.Add)
            {
                return;
            }

            if (lstReceivedMessages.Items.Count == 0)
            {
                return;
            }

            var lastIndex = lstReceivedMessages.Items.Count - 1;
            
            if (lastIndex < 0)
            {
                return;
            }

            // Waits for the UI to finish layout updates, then scrolls.
            // BeginInvoke with Background priority runs after rendering,
            // ensuring the ScrollViewer scrolls to the bottom once the new message appears.
            Dispatcher.BeginInvoke(new Action(() =>
            {
                _messagesScrollViewer?.ScrollToEnd();
            }), DispatcherPriority.Background);
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
            popupEmoji.Visibility = Visibility.Collapsed;
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
            if (_scrollDirection == -1)
            {
                // Scroll left
                emojiScrollViewer.ScrollToHorizontalOffset(emojiScrollViewer.HorizontalOffset - 20);
            }
            else if (_scrollDirection == 1)
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

        /// <summary>
        /// Updates the ViewModel with the current rendered width of the message
        /// input TextBox whenever its size changes. This keeps the ViewModel's
        /// width-dependent calculations (emoji scaling, popup width, etc.)
        /// synchronized with the actual UI layout.
        /// </summary>
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

        /// <summary>
        /// Saves the roster panel width when the vertical splitter drag operation completes.
        /// </summary>
        private void VerticalSplitter_DragCompleted(object sender, DragCompletedEventArgs e) 
        { 
            double actualWidth = ColRoster.ActualWidth;
            if (actualWidth < 20)
            {
                actualWidth = 20;
            }
            
            Settings.Default.RosterWidth = actualWidth; 
            Settings.Default.Save(); 
        }

        /// <summary>
        /// Restricts the vertical splitter movement by enforcing a maximum width
        /// for the roster (half of the total window width).
        /// Cancels the drag when the limit would be exceeded.
        /// </summary>
        private void VerticalSplitter_PreviewMouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed)
            {
                return;
            }

            double totalWidth = GrdMain.ActualWidth;

            // Maximum allowed width for the roster (half of the total width)
            double maxRosterWidth = totalWidth / 2.0;

            // Mouse position relative to GrdMain
            Point mousePosition = e.GetPosition(GrdMain);

            // The width the roster would have if the splitter moved here
            double newRosterWidth = mousePosition.X;

            // Prevents the roster from exceeding the maximum width
            if (newRosterWidth > maxRosterWidth)
            {
                e.Handled = true;
                return;
            }

            // Prevents the roster from shrinking below 40 px
            if (newRosterWidth < 40)
            {
                e.Handled = true;
                return;
            }
        }

        /// <summary>
        /// Reacts to ViewModel layout-related changes.
        /// - Updates the bottom row height live when the splitter moves.
        /// </summary>
        private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            // Live update when splitter moves
            if (e.PropertyName == nameof(viewModel.InputAreaHeight))
            {
                RowBottomRight.Height = new GridLength(viewModel.InputAreaHeight, GridUnitType.Pixel);
            }
        }

        /// <summary> 
        /// Restores all persisted layout dimensions (roster width and input area height) 
        /// after the first valid layout pass of the window. 
        /// This ensures the restore occurs only once, 
        /// after WPF has completed its initial layout calculations.
        /// </summary>
        private void Window_LayoutUpdated(object sender, EventArgs e)
        {
            if (!_pendingInitialRestore)
            {
                return;
            }

            double rosterWidth = Settings.Default.RosterWidth;
            if (rosterWidth < 20)
            {
                rosterWidth = 20;
            }

            // Restores the roster width
            ColRoster.Width = new GridLength(rosterWidth, GridUnitType.Pixel);

            // Restores bottom input area height
            double savedHeight = Settings.Default.InputAreaHeight;
            if (double.IsNaN(savedHeight) || savedHeight < _MIN_INPUT_AREA_HEIGHT)
            {
                savedHeight = _MIN_INPUT_AREA_HEIGHT;
            }

            RowBottomRight.Height = new GridLength(savedHeight, GridUnitType.Pixel);

            _pendingInitialRestore = false;
        }

        private void Window_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            double maxRosterWidth = this.ActualWidth / 2.0; 
            
            // Clamps the current roster width if it exceeds the new max
            if (ColRoster.Width.Value > maxRosterWidth) 
            { 
                ColRoster.Width = new GridLength(maxRosterWidth, GridUnitType.Pixel); 
            } 
            
            // Applies the max constraint
            GrdLeft.MaxWidth = maxRosterWidth;
        }
    }
}