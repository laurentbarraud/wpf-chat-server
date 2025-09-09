/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 8th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.View;
using chat_client.MVVM.ViewModel;
using Hardcodet.Wpf.TaskbarNotification;
using System.Collections.Specialized;
using System.Configuration;
using System.Net.Sockets;
using System.Text.RegularExpressions;
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

        public MainWindow()
        {
            InitializeComponent();

            // ViewModel binding
            ViewModel = new MainViewModel();
            this.DataContext = ViewModel;

            // Subscribes to message collection changes to trigger autoscroll
            ViewModel.Messages.CollectionChanged += Messages_CollectionChanged;

            // Initializes the scroll timer for emoji panel
            scrollTimer = new DispatcherTimer();
            scrollTimer.Interval = TimeSpan.FromMilliseconds(50);
            scrollTimer.Tick += ScrollTimer_Tick;
        }


        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Restores last used IP address
            txtIPAddress.Text = chat_client.Properties.Settings.Default.LastIPAddressUsed;

            // Apply watermarks on startup
            OnTextBoxTextChanged(txtUsername, null);
            OnTextBoxTextChanged(txtIPAddress, null);

            // Synchronizes the toggle button with the current theme
            ThemeToggle.IsChecked = Properties.Settings.Default.AppTheme == "Dark";

            // Synchronizes the encrypted image visibilty with the current setting
            imgEncryptionStatus.Visibility = Properties.Settings.Default.UseEncryption 
                ? Visibility.Visible : Visibility.Collapsed;
        
            // Sets focus to username field
            txtUsername.Focus();
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

        private void cmdSend_Click(object sender, RoutedEventArgs e)
        {
            // Prevent sending if message is empty or client is not connected
            if (!string.IsNullOrEmpty(MainViewModel.Message) && MainViewModel._server.IsConnected)
            {
                MainViewModel._server.SendMessageToServer(MainViewModel.Message);
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
        /// Initializes the tray icon, context menu, and mouse interaction events.
        /// </summary>
        private void HideToTray()
        {
            var trayIcon = (TaskbarIcon)FindResource("TrayIcon");

            // Hide the main window
            this.Hide();
            this.ShowInTaskbar = false;
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

            if (e.Key == Key.Escape)
            {
                HideToTray();
            }

            // if the Ctrl key is pressed twice within one second
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
            // Scroll to the last message when a new one is added
            if (e.Action == NotifyCollectionChangedAction.Add && lstMessagesReceived.Items.Count > 0)
            {
                lstMessagesReceived.ScrollIntoView(lstMessagesReceived.Items[lstMessagesReceived.Items.Count - 1]);
            }
        }

        /// <summary>
        /// This method dynamically applies the correct watermark according to field,
        /// language and theme. It restores the background if the field is filled in.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnTextBoxTextChanged(object sender, TextChangedEventArgs e)
        {
            // Ensures the sender is a TextBox
            if (sender is not TextBox currentTextBox)
                return;

            // Identifies which field is being edited
            string fieldKey = null;

            if (currentTextBox.Name == "txtUsername")
                fieldKey = "txtUsername";
            else if (currentTextBox.Name == "txtIPAddress")
                fieldKey = "txtIPAddress";

            if (fieldKey == null)
                return;

            // Gets current language and theme from settings
            string currentLanguage = Properties.Settings.Default.AppLanguage; // "en", "fr"
            string currentTheme = Properties.Settings.Default.AppTheme;       // "light", "dark"

            // Builds the resource key for the watermark brush
            string themeSuffix = currentTheme == "dark" ? "_dark" : "";
            string watermarkKey = $"{fieldKey}_background_{currentLanguage}{themeSuffix}";

            // Checks if the textbox is empty
            bool isTextBoxEmpty = string.IsNullOrWhiteSpace(currentTextBox.Text);

            if (isTextBoxEmpty)
            {
                // Applies watermark brush if found
                if (TryFindResource(watermarkKey) is ImageBrush watermarkBrush)
                {
                    currentTextBox.Background = watermarkBrush;
                }

                // Disables connect button if username is empty
                if (currentTextBox.Name == "txtUsername")
                {
                    cmdConnectDisconnect.IsEnabled = false;
                }
            }
            else
            {
                // Restores themed background
                if (TryFindResource("BackgroundColor") is Brush themeBrush)
                {
                    currentTextBox.Background = themeBrush;
                }
                else
                {
                    currentTextBox.Background = null;
                }

                // Enables connect button if username is filled
                if (currentTextBox.Name == "txtUsername")
                {
                    cmdConnectDisconnect.IsEnabled = true;
                }
            }
        }

        /// <summary>
        /// Resets the arrow icon to point right when popup is closed
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void popupEmojiPanel_Closed(object sender, EventArgs e)
        {
            // Re-enable the button and restore the default icon
            cmdEmojiPanel.IsEnabled = true;
            imgEmojiPanel.Source = new BitmapImage(new Uri("/Resources/right-arrow.png", UriKind.Relative));
            isEmojiPanelOpen = false;
        }

        /// <summary>
        /// Restores the main window from the system tray and disposes the tray icon.
        /// </summary>
        private void RestoreFromTray()
        {
            if (trayIcon != null)
            {
                trayIcon.Dispose();
                trayIcon = null;
            }

            this.Show();
            this.WindowState = WindowState.Normal;
            this.ShowInTaskbar = true;
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


        private void TrayIcon_TrayMouseDoubleClick(object sender, RoutedEventArgs e)
        {
            // Simulates clicking "Open" from the tray menu
            TrayMenu_Open_Click(sender, e);
        }

        /// <summary>
        /// Starts a timer when the mouse hovers over the tray icon.
        /// If the cursor remains for more than 2 seconds, the application shuts down.
        /// </summary>
        private void TrayIcon_MouseMove(object sender, System.Windows.Forms.MouseEventArgs e)
        {
            if (hoverTimer == null)
            {
 
                hoverTimer = new System.Windows.Forms.Timer() { Interval = 2000 };
                hoverTimer.Tick += (s, args) =>
                {
                    hoverTimer.Stop();
                    Application.Current.Shutdown();
                };
                hoverTimer.Start();
            }
        }

        private void TrayMenu_Open_Click(object sender, RoutedEventArgs e)
        {
            this.Show();
            this.WindowState = WindowState.Normal;
            this.ShowInTaskbar = true;
        }

        private void TrayMenu_Quit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }


        private void ThemeToggle_Checked(object sender, RoutedEventArgs e)
        {
            // Apply dark theme to this window with fade animation
            ThemeManager.ApplyTheme(true);

            // Save user preference
            Properties.Settings.Default.AppTheme = "Dark";
            Properties.Settings.Default.Save();
        }

        private void ThemeToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            // Apply light theme to this window with fade animation
            ThemeManager.ApplyTheme(false);

            // Save user preference
            Properties.Settings.Default.AppTheme = "Light";
            Properties.Settings.Default.Save();
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
            if (txtMessageToSend.Text == "" || MainViewModel._server.IsConnected == false)
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
    }
}