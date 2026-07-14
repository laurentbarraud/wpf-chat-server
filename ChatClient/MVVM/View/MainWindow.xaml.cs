/// <file>MainWindow.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>July 15th, 2026</date>

using ChatClient.Helpers;
using ChatClient.MVVM.Model;
using ChatClient.Properties;
using ChatClient.Resources;
using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace ChatClient.MVVM.View
{
    /// <summary>
    /// Modern chat window. Fully aligned with the new layout (no roster, no GrdLeft/Right).
    /// Preserves all behaviors from the legacy version: emoji scroll, tray icon,
    /// monitor window, theme toggle, watermark refresh, auto-scroll, send logic, etc.
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        // PRIVATE FIELDS

        /// <summary>
        /// Stores the base height of the emoji panel
        /// </summary>
        private int _emojiPanelHeight = 20;

        /// <summary>
        /// Timestamp of the last CTRL key press for double-press detection
        /// </summary>
        private DateTime _lastCtrlPressDateTime = DateTime.MinValue;

        /// <summary>
        /// Reference to the ScrollViewer inside the messages ListBox for auto-scrolling.
        /// </summary>
        private ScrollViewer? _messagesScrollViewer;

        /// <summary>
        /// Stores the minimum allowed height for the message input area 
        /// to prevent it from collapsing during splitter drag.
        /// </summary>
        private const double _MIN_INPUT_AREA_HEIGHT = 34;

        /// <summary>
        /// Flag indicating that the input area height must be restored once,
        /// after the first full layout pass.
        /// </summary>
        private bool _pendingInitialRestore = true;

        /// <summary>
        /// Scroll direction: -1 for left, 1 for right, 0 for no scroll.
        /// </summary>
        private int _scrollDirection = 0;

        /// <summary>
        /// DispatcherTimer for handling continuous emoji panel scrolling when hovering over scroll buttons.
        /// </summary>
        private readonly DispatcherTimer scrollTimer;

        /// PUBLIC PROPERTIES AND EVENTS
        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Gets or sets the base height of the emoji panel.
        /// </summary>
        public int EmojiPanelHeight
        {
            get { return _emojiPanelHeight; }
            set
            {
                _emojiPanelHeight = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Indicates whether the client is connected.
        /// </summary>
        public bool IsConnected
        {
            get { return App.ViewModel?.ClientConn != null && App.ViewModel.ClientConn.IsConnected; }
        }

        /// <summary>
        /// Indicates whether the window is wide enough to enlarge emoji UI.
        /// </summary>
        public bool IsWindowWide
        {
            get { return TxtMessageInputField.ActualWidth > 600 || WindowState == WindowState.Maximized; }
        }

        /// <summary>
        /// MainWindow constructor.
        /// Initializes theme, tray icon, emoji scroll timer, watermarks, etc.
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();

            // DataContext is set globally in App.xaml.cs
            this.DataContext = App.ViewModel;

            // Events subscriptions
            Loaded += MainWindow_Loaded;
            GrdMain.SizeChanged += GrdMain_SizeChanged;
            App.ViewModel.PropertyChanged -= ViewModel_PropertyChanged;
            App.ViewModel.PropertyChanged += ViewModel_PropertyChanged;

            LayoutUpdated += MainWindow_LayoutUpdated;

            // Emoji scroll timer initialization
            scrollTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(50)
            };
            scrollTimer.Tick += ScrollTimer_Tick;

            // Theme initialization based on saved settings.
            // This ensures the correct theme is applied before the window is rendered.
            ThemeManager.ApplyTheme(Settings.Default.AppTheme.ToLower() == "dark");
            ApplyWatermarks();

            // Sets the theme toggle state based on the current theme.
            ThemeToggle.IsChecked = Settings.Default.AppTheme?.ToLower() == "dark";

            // Tooltips localization
            CmdSettings.ToolTip = LocalizationManager.GetString("SettingsToolTip");
            CmdScrollLeft.ToolTip = LocalizationManager.GetString("ScrollLeftToolTip");
            CmdScrollRight.ToolTip = LocalizationManager.GetString("ScrollRightToolTip");

            // Initializes the server IP address field with the last saved value.
            TxtServerIPAddress.Text = Settings.Default.ServerIPAddress;

            // Initializes localization
            string storedLanguageCode = Settings.Default.AppLanguageCode;
            LocalizationManager.InitializeLocalization(storedLanguageCode);

            // Sets the localized label text for the connected users list.
            lblConnectedUsers.Content = Strings.ConnectedUsersListLabelText;

            // Hides the monitor button in release mode until toggled via shortcut
            CmdMonitor.BeginAnimation(UIElement.OpacityProperty, null);
            CmdMonitor.Opacity = 0;
            CmdMonitor.IsHitTestVisible = false;

            TxtUsername.Focus();
        }

        /// <summary>
        /// Handles initialization tasks once the MainWindow has finished loading.
        /// Subscribes to global view model events, restores input area height,
        /// refreshes watermarks, and sets focus.
        /// </summary>
        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Subscribes to global ViewModel events
            App.ViewModel.Messages.CollectionChanged -= Messages_CollectionChanged;
            App.ViewModel.Messages.CollectionChanged += Messages_CollectionChanged;

            // Restores input area height from settings
            double inputAreaSavedHeight = Settings.Default.InputAreaHeight;

            if (double.IsNaN(inputAreaSavedHeight) || inputAreaSavedHeight < _MIN_INPUT_AREA_HEIGHT)
            {
                inputAreaSavedHeight = _MIN_INPUT_AREA_HEIGHT;
            }

            App.ViewModel.InputAreaHeight = inputAreaSavedHeight;

            // Refreshes UI watermarks
            ApplyWatermarks();

#if DEBUG
            CmdMonitor.Opacity = 1;
            CmdMonitor.IsHitTestVisible = true;
#endif

            TxtUsername.Focus();
        }

        /// <summary>
        /// Refreshes watermark texts and visibility after theme/language changes.
        /// </summary>
        public void ApplyWatermarks()
        {
            // Refreshes localized watermark resources
            App.ViewModel.InitializeWatermarkResources();

            // Forces the binding engine to refresh the watermark text.
            // UpdateTarget() re-evaluates the binding source immediately, which is required
            // after dynamic theme or language changes since WPF does not auto-refresh them.
            TxtUsernameWatermark.GetBindingExpression(TextBlock.TextProperty)?.UpdateTarget();
            TxtIPAddressWatermark.GetBindingExpression(TextBlock.TextProperty)?.UpdateTarget();
            TxtMessageInputFieldWatermark.GetBindingExpression(TextBlock.TextProperty)?.UpdateTarget();

            // Forces the visibility bindings to re-evaluate. This ensures the watermark
            // correctly appears or hides after UI state changes (focus, input, theme switch).
            TxtUsernameWatermark.GetBindingExpression(TextBlock.VisibilityProperty)?.UpdateTarget();
            TxtIPAddressWatermark.GetBindingExpression(TextBlock.VisibilityProperty)?.UpdateTarget();
            TxtMessageInputFieldWatermark.GetBindingExpression(TextBlock.VisibilityProperty)?.UpdateTarget();

            // Refreshes the "Connected" / IP display text
            if (App.ViewModel.IsConnected)
            {
                App.ViewModel.CurrentIPDisplay = $"– {LocalizationManager.GetString("Connected")} –";
            }
            else
            {
                App.ViewModel.CurrentIPDisplay = Settings.Default.ServerIPAddress;
            }

            // Notifies the UI that the bound property has changed.
            // OnPropertyChanged(nameof(...)) forces WPF to re-evaluate all bindings
            // referencing this property so the updated value is pushed to the UI immediately.
            App.ViewModel.OnPropertyChanged(nameof(App.ViewModel.CurrentIPDisplay));
        }

        /// <summary>
        /// Shows the emoji popup.
        /// </summary>
        private void CmdEmojiPanel_Click(object sender, RoutedEventArgs e)
        {
            popupEmoji.VerticalOffset = -popupEmoji.ActualHeight;
            popupEmoji.Visibility = Visibility.Visible;
            popupEmoji.IsOpen = true;
        }

        /// <summary>
        /// Opens or closes the monitor window.
        /// </summary>
        private void CmdMonitor_Click(object sender, RoutedEventArgs e)
        {
            ToggleMonitorWindow();
        }

        /// <summary>
        /// Starts scrolling left when mouse enters the left arrow.
        /// </summary>
        /// <param name="sender">Left arrow button.</param>
        /// <param name="e">Event args.</param>
        private void CmdScrollLeft_MouseEnter(object sender, MouseEventArgs e)
        {
            _scrollDirection = -1;
            scrollTimer.Start();
        }

        /// <summary>
        /// Stops scrolling when mouse leaves the left arrow.
        /// </summary>
        /// <param name="sender">Left arrow button.</param>
        /// <param name="e">Event args.</param>
        private void CmdScrollLeft_MouseLeave(object sender, MouseEventArgs e)
        {
            scrollTimer.Stop();
        }

        /// <summary>
        /// Starts scrolling right when mouse enters the right arrow.
        /// </summary>
        /// <param name="sender">Right arrow button.</param>
        /// <param name="e">Event args.</param>
        private void CmdScrollRight_MouseEnter(object sender, MouseEventArgs e)
        {
            _scrollDirection = 1;
            scrollTimer.Start();
        }

        /// <summary>
        /// Stops scrolling when mouse leaves the right arrow.
        /// </summary>
        /// <param name="sender">Right arrow button.</param>
        /// <param name="e">Event args.</param>
        private void CmdScrollRight_MouseLeave(object sender, MouseEventArgs e)
        {
            scrollTimer.Stop();
        }

        /// <summary>
        /// Sends a message asynchronously.
        /// Validates connection state, dispatches the message, and updates the UI accordingly.
        /// </summary>
        private async void CmdSend_Click(object sender, RoutedEventArgs e)
        {
            // Quick validation: prevents sending when the message is empty or the connection
            // has not completed its handshake.
            // This avoids unnecessary async calls and keeps the UI responsive under unstable
            // network conditions.

            if (string.IsNullOrEmpty(App.ViewModel.MessageToSend) ||
                App.ViewModel.ClientConn?.IsConnected != true ||
                App.ViewModel.ClientConn?.IsEstablished != true)
            {
                ClientLogger.Log("Send blocked: connection not yet fully established", ClientLogLevel.Debug);
                return;
            }

            try
            {
                bool msgSent = await App.ViewModel.ClientConn.SendMessageAsync(App.ViewModel.MessageToSend, CancellationToken.None);

                if (msgSent)
                {
                    // Clears input field and restores focus for fast typing.
                    App.ViewModel.MessageToSend = "";
                    TxtMessageInputField.Focus();
                }
                else
                {
                    // Inserts a localized system message into the observable collection
                    // to signal the failure.
                    // Because Messages is bound to the UI, adding a new ChatMessage
                    // automatically refreshes the view without blocking the UI thread.
                    // Marking it as IsSystemMessage allows the UI to style it differently.
                    App.ViewModel.Messages.Add(new ChatMessage
                    {
                        Text = $"# {LocalizationManager.GetString("SendingFailed")} #",
                        Sender = "System",
                        TimeStamp = DateTime.Now.ToString("HH:mm"),
                        IsSystemMessage = true
                    });
                }
            }
            catch (OperationCanceledException)
            {
                ClientLogger.Log("Send operation cancelled", ClientLogLevel.Debug);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"Send failed: {ex.Message}", ClientLogLevel.Error);

                App.ViewModel.Messages.Add(new ChatMessage
                {
                    Text = $"# {LocalizationManager.GetString("SendingFailed")} #",
                    Sender = "System",
                    TimeStamp = DateTime.Now.ToString("HH:mm"),
                    IsSystemMessage = true
                });
            }
        }

        /// <summary>
        /// Opens SettingsWindow or monitor (CTRL+Click).
        /// </summary>
        private void CmdSettings_Click(object sender, RoutedEventArgs e)
        {
            if (Keyboard.Modifiers == ModifierKeys.Control)
            {
                ToggleMonitorWindow();
                return;
            }

            var existing = Application.Current.Windows.OfType<SettingsWindow>().FirstOrDefault();
            if (existing != null)
            {
                existing.Close();
                return;
            }

            var settingsWindow = new SettingsWindow()
            {
                Owner = this,
                DataContext = App.ViewModel
            };

            settingsWindow.Show();
        }

        /// <summary>
        /// Inserts an emoji into the message input field.
        /// </summary>
        /// <param name="sender">Button containing emoji.</param>
        /// <param name="e">Event args.</param>
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
        /// Finds a child of type T in the visual tree.
        /// </summary>
        /// <typeparam name="T">Type to find.</typeparam>
        /// <param name="parent">Parent element.</param>
        /// <returns>Child or null.</returns>
        private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
        {
            int childCount = VisualTreeHelper.GetChildrenCount(parent);

            for (int i = 0; i < childCount; i++)
            {
                DependencyObject child = VisualTreeHelper.GetChild(parent, i);

                if (child is T typed)
                {
                    return typed;
                }

                T? deeper = FindVisualChild<T>(child);
                if (deeper != null)
                {
                    return deeper;
                }
            }

            return null;
        }

        /// <summary>
        /// Refreshes the stored width of the right grid in the ViewModel when the main grid size changes.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void GrdMain_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            App.ViewModel.RightGridWidth = GrdMain.ActualWidth;
        }

        /// <summary>
        /// Hides the monitor button with a fade‑out animation 
        /// when the monitor window is closed.
        /// </summary>
        public void HideMonitorButton()
        {
#if !DEBUG
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(1500))
            {
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            };

            fadeOut.Completed += (s, e) =>
            {
                CmdMonitor.Opacity = 0;
            };

            CmdMonitor.BeginAnimation(OpacityProperty, fadeOut);
#endif
        }

        /// <summary>
        /// Saves InputAreaHeight after drag.
        /// </summary>
        private void HorizontalSplitter_DragCompleted(object sender, DragCompletedEventArgs e)
        {
            Settings.Default.InputAreaHeight = App.ViewModel.InputAreaHeight;
            Settings.Default.Save();
        }

        /// <summary>
        /// Handles horizontal splitter drag (InputAreaHeight).
        /// </summary>
        private void HorizontalSplitter_DragDelta(object sender, DragDeltaEventArgs e)
        {
            App.ViewModel.InputAreaHeight = Math.Max(_MIN_INPUT_AREA_HEIGHT, App.ViewModel.InputAreaHeight - e.VerticalChange);
        }

        /// <summary>
        /// Enforces minimum heights during splitter drag.
        /// </summary>
        private void HorizontalSplitter_PreviewMouseMove(object sender, MouseEventArgs e)
        {
            if (e.LeftButton != MouseButtonState.Pressed)
            {
                return;
            }

            double total = GrdMain.ActualHeight;
            Point pos = e.GetPosition(GrdMain);

            double newBottom = total - pos.Y;

            if (newBottom < 66)
            {
                e.Handled = true;
                return;
            }

            double newMessages = total - newBottom - 5;

            if (newMessages < 20)
            {
                e.Handled = true;
            }
        }

        /// <summary>
        /// Opens the connected users popup after layout is ready.
        /// Prevents the popup from appearing too small and blocking UI hit‑testing.
        /// </summary>
        private void lblConnectedUsers_MouseEnter(object sender, MouseEventArgs e)
        {
            if (!App.ViewModel.IsConnected)
            {
                return;
            }
 
            ConnectedUsersPopup.IsOpen = true;
        }

        /// <summary>
        /// Captures the ScrollViewer of the messages list.
        /// </summary>
        private void lstReceivedMessages_Loaded(object sender, RoutedEventArgs e)
        {
            _messagesScrollViewer = FindVisualChild<ScrollViewer>(lstReceivedMessages);
        }

        /// <summary>
        /// Monitors layout updates to apply the initial input area height restoration from settings.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void MainWindow_LayoutUpdated(object? sender, EventArgs e)
        {
            if (!_pendingInitialRestore)
            {
                return;
            }

            double savedHeight = Settings.Default.InputAreaHeight;

            // Enforces a minimum height to prevent the input area from collapsing if the saved value is invalid.
            if (double.IsNaN(savedHeight) || savedHeight < 34)
            {
                savedHeight = 34;
            }

            // Applies the saved height to the input area row.
            // This ensures that the layout is restored correctly on startup,
            RowBottomRight.Height = new GridLength(savedHeight, GridUnitType.Pixel);

            // Marks the initial restore as done to prevent re-applying it on subsequent layout updates.
            _pendingInitialRestore = false;
        }

        /// <summary>
        /// Handles keyboard shortcuts.
        /// </summary>
        private void MainWindow_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            // If ReduceToTray is disabled, no tray-related shortcuts should apply
            if (!App.ViewModel.ReduceToTray)
            {
                return;
            }

            // ESC : reduces the application to the system tray
            if (e.Key == Key.Escape)
            {
                ((App)Application.Current).ApplyReduceToTray();
                return;
            }

            // Detects double CTRL press within 1 second and reduces to tray
            if (e.Key == Key.LeftCtrl || e.Key == Key.RightCtrl)
            {
                var nowDateTime = DateTime.Now;

                // If the previous CTRL press was less than 1 second ago, triggers tray reduction
                if ((nowDateTime - _lastCtrlPressDateTime).TotalMilliseconds < 1000)
                {
                    ((App)Application.Current).ApplyReduceToTray();
                }

                // Updates last CTRL press timestamp
                _lastCtrlPressDateTime = nowDateTime;
            }
        }

        /// <summary>
        /// Auto-scrolls to the latest message.
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

            Dispatcher.BeginInvoke(new Action(() =>
            {
                _messagesScrollViewer?.ScrollToEnd();
            }), DispatcherPriority.Background);
        }

        /// <summary>
        /// Standard INotifyPropertyChanged implementation.
        /// </summary>
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        /// <summary>
        /// Handles emoji popup closing.
        /// </summary>
        private void popupEmoji_Closed(object sender, EventArgs e)
        {
            popupEmoji.Visibility = Visibility.Collapsed;
        }

        /// <summary>
        /// Refreshes localized strings in the main window after a language change.
        /// </summary>
        public void RefreshMainWindowLocalization()
        {
            App.ViewModel.ConnectedUsersListLabelText =
                LocalizationManager.GetString("ConnectedUsersListLabelText");

            if (App.ViewModel.IsConnected)
            {
                App.ViewModel.CurrentIPDisplay =
                    $"– {LocalizationManager.GetString("Connected")} –";
            }
        }

        /// <summary>
        /// Emoji auto-scroll timer tick.
        /// </summary>
        private void ScrollTimer_Tick(object? sender, EventArgs e)
        {
            if (_scrollDirection == -1)
            {
                emojiScrollViewer.ScrollToHorizontalOffset(emojiScrollViewer.HorizontalOffset - 20);
            }
            else if (_scrollDirection == 1)
            {
                emojiScrollViewer.ScrollToHorizontalOffset(emojiScrollViewer.HorizontalOffset + 20);
            }
        }

        /// <summary>
        /// Applies dark theme.
        /// </summary>
        private void ThemeToggle_Checked(object sender, RoutedEventArgs e)
        {
            Settings.Default.AppTheme = "dark";
            Settings.Default.Save();

            ThemeManager.ApplyTheme(true);
            ApplyWatermarks();
        }

        /// <summary>
        /// Applies light theme.
        /// </summary>
        private void ThemeToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            Settings.Default.AppTheme = "light";
            Settings.Default.Save();

            ThemeManager.ApplyTheme(false);
            ApplyWatermarks();
        }

        /// <summary>
        /// Toggles the monitor window.
        /// </summary>
        public void ToggleMonitorWindow()
        {
            // If a monitor window already exists, closes it.
            var existingMonitorWindow = Application.Current.Windows.OfType<MonitorWindow>().FirstOrDefault();
            if (existingMonitorWindow != null)
            {
                existingMonitorWindow.Close();
                return;
            }

            // Creates a new monitor window using the global ViewModel.
            var monitorWindow = new MonitorWindow
            {
                Owner = this
            };

#if !DEBUG
            // Ensures the monitor button becomes visible again when toggled via shortcuts.
            CmdMonitor.BeginAnimation(OpacityProperty, null);
            CmdMonitor.IsHitTestVisible = true;

            if (CmdMonitor.Opacity == 0)
            {
                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(1500))
                {
                    EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
                };

                CmdMonitor.BeginAnimation(OpacityProperty, fadeIn);
            }
#endif

            monitorWindow.Show();
        }

        /// <summary>
        /// Handles Enter / Shift+Enter / Ctrl+Enter / Alt+Enter in the message input.
        /// </summary>
        private void TxtMessageInputField_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            bool isEnter = e.Key == Key.Enter || e.Key == Key.Return;
            bool shift = Keyboard.IsKeyDown(Key.LeftShift) || Keyboard.IsKeyDown(Key.RightShift);
            bool ctrl = Keyboard.IsKeyDown(Key.LeftCtrl) || Keyboard.IsKeyDown(Key.RightCtrl);
            bool alt = Keyboard.IsKeyDown(Key.LeftAlt) || Keyboard.IsKeyDown(Key.RightAlt);

            if (isEnter && shift)
            {
                return;
            }

            if (isEnter && (ctrl || alt))
            {
                if (sender is TextBox tb)
                {
                    int caret = tb.CaretIndex;
                    tb.Text = tb.Text.Insert(caret, Environment.NewLine);
                    tb.CaretIndex = caret + Environment.NewLine.Length;
                    e.Handled = true;
                }

                return;
            }

            if (isEnter)
            {
                e.Handled = true;

                if (sender is TextBox tb)
                {
                    DependencyObject parent = VisualTreeHelper.GetParent(tb);

                    while (parent != null && parent is not Window)
                    {
                        if (parent is Grid grid)
                        {
                            if (grid.FindName("CmdSend") is Button sendButton)
                            {
                                sendButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                                break;
                            }
                        }

                        parent = VisualTreeHelper.GetParent(parent);
                    }
                }
            }
        }

        /// <summary>
        /// Dynamically adjusts the height of the message input TextBox to fit its content as the user types.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void TxtMessageInputField_TextChanged(object sender, TextChangedEventArgs e)
        {
            // Resets height to allow recalculation
            TxtMessageInputField.Height = Double.NaN;
            TxtMessageInputField.UpdateLayout();

            // Sets height to content
            TxtMessageInputField.Height = TxtMessageInputField.ExtentHeight +
                TxtMessageInputField.Padding.Top + TxtMessageInputField.Padding.Bottom;
        }

        /// <summary>
        /// Handles Enter in the IP field.
        /// </summary>
        private void TxtServerIPAddress_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                // Executes the global connect/disconnect command.
                App.ViewModel.ConnectDisconnectCommand.Execute(null);
                e.Handled = true;
            }
        }

        /// <summary>
        /// Handles Enter in the Username field.
        /// </summary>
        private void TxtUsername_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                // Executes the global connect/disconnect command.
                App.ViewModel.ConnectDisconnectCommand.Execute(null);
                e.Handled = true;
            }
        }

        /// <summary>
        /// Updates the text of the label for the connected users list.
        /// </summary>
        public void UpdateConnectedUsersLabelText()
        {
            lblConnectedUsers.Content = LocalizationManager.GetString("ConnectedUsersListLabelText");
        }

        /// <summary>
        /// Updates the input area height in the UI when the corresponding ViewModel property changes.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(App.ViewModel.InputAreaHeight))
            {
                RowBottomRight.Height = new GridLength(App.ViewModel.InputAreaHeight, GridUnitType.Pixel);
            }
        }
    }
}

