/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.8</version>
/// <date>September 7th, 2025</date>
/// 
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


namespace chat_client
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainViewModel ViewModel { get; set; }

        public MainWindow()
        {
            InitializeComponent();
            ViewModel = new MainViewModel();
            this.DataContext = ViewModel;

            // Subscribe to message collection changes to trigger autoscroll
            ViewModel.Messages.CollectionChanged += Messages_CollectionChanged;
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