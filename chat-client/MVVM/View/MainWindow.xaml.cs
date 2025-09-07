/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.9</version>
/// <date>September 7th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.View;
using chat_client.MVVM.ViewModel;
using System.Collections.Specialized;
using System.Configuration;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Hardcodet.Wpf.TaskbarNotification;

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

        // List of commonly used workplace emojis
        private readonly List<string> EmojiList = new()
{
            "😀", "😁", "😂", "🤣", "😊", "😎", "😉", "😇",
            "🙃", "😅", "😐", "😶", "😬", "🤔", "🤨", "😏",
            "😤", "😢", "😭", "😡", "👍", "👎", "🙏", "💼"
};

        // Tracks popup state
        private bool isEmojiPanelOpen = false;

        public MainWindow()
        {
            InitializeComponent();
            ViewModel = new MainViewModel();
            this.DataContext = ViewModel;

            // Subscribes to message collection changes to trigger autoscroll
            ViewModel.Messages.CollectionChanged += Messages_CollectionChanged;

            // Initializes the list
            emojiItems.ItemsSource = EmojiList;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Restores last used IP address
            txtIPAddress.Text = chat_client.Properties.Settings.Default.LastIPAddressUsed;

            // Synchronizes the toggle button with the current theme
            ThemeToggle.IsChecked = Properties.Settings.Default.AppTheme == "Dark";

            // Sets focus to username field
            txtUsername.Focus();
        }

        public void cmdConnectDisconnect_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.ConnectDisconnect();
        }

        /// <summary>
        /// Toggles the emoji popup panel and updates the arrow icon.
        /// </summary>
        private void cmdEmojiPanel_Click(object sender, RoutedEventArgs e)
        {
            if (!isEmojiPanelOpen)
            {
                popupEmojiPanel.IsOpen = true;
                imgEmojiPanel.Source = new BitmapImage(new Uri("/Resources/left-arrow.png", UriKind.Relative));
                isEmojiPanelOpen = true;
            }
            else
            {
                popupEmojiPanel.IsOpen = false;
                imgEmojiPanel.Source = new BitmapImage(new Uri("/Resources/right-arrow.png", UriKind.Relative));
                isEmojiPanelOpen = false;
            }
        }

        private void cmdSend_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(MainViewModel.Message))
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


        private void OnTextBoxTextChanged(object sender, TextChangedEventArgs e)
        {
            // Ensures the sender is a textbox before proceeding
            if (sender is not TextBox txtbox)
                return;

            // Determines the appropriate background resource key based on the textbox's name
            string? resourceKey = null;

            if (txtbox.Name == "txtUsername")
            {
                resourceKey = "txtUsername_background";

            }
            else if (txtbox.Name == "txtIPAddress")
            {
                resourceKey = "txtIPAddress_background";
            }
            
            // If the dark mode is set
            if (Properties.Settings.Default.AppTheme == "Dark")
            {
                resourceKey += "_dark";
            }

            // Checks if the textbox is empty or contains only whitespace
            bool isTextBoxEmpty = string.IsNullOrWhiteSpace(txtbox.Text);

            if (isTextBoxEmpty)
            {
                // If the field is empty, apply the watermark background
                if (resourceKey != null && TryFindResource(resourceKey) is ImageBrush watermarkBrush)
                {
                    txtbox.Background = watermarkBrush;
                }

                if (txtbox.Name == "txtUsername")
                {
                    cmdConnectDisconnect.IsEnabled = false;
                }
            }

            // the textbox is not empty
            else
            {
                // If the field contains text, restore the themed background
                if (resourceKey != null && TryFindResource("BackgroundColor") is Brush themeBrush)
                {
                    txtbox.Background = themeBrush;
                }
                else
                {
                    // If no theme brush is found, fallback to default background
                    txtbox.Background = null;
                }

                if (txtbox.Name == "txtUsername")
                {
                    cmdConnectDisconnect.IsEnabled = true;
                }
            }
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