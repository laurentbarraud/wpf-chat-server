/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.6</version>
/// <date>September 1st, 2025</date>

using chat_client.MVVM.ViewModel;
using chat_client.Net;
using System.Configuration;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using chat_client.Helpers;


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
        }


        public void cmdConnect_Click(object sender, RoutedEventArgs e)
        {
            // Check if user is already connected
            if (MainViewModel.IsConnectedToServer)
            {
                // --- DISCONNECT LOGIC ---
                try
                {
                    // Close the connection to the server
                    MainViewModel._server.DisconnectFromServer();

                    // Reset UI state
                    cmdConnect.Content = "_Connect"; // Button text back to "Connect"
                    txtUsername.IsEnabled = true;
                    txtIPAddress.IsEnabled = true;

                    // Clear the bound collections instead of Items.Clear()
                    ViewModel.Users.Clear();
                    ViewModel.Messages.Clear();

                    this.Title = "WPF Chat Server";
                    spnCenter.Visibility = Visibility.Hidden;
                    MainViewModel.IsConnectedToServer = false;
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error while disconnecting: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else
            {
                // --- CONNECT LOGIC ---
                if (!string.IsNullOrEmpty(MainViewModel.Username))
                {
                    try
                    {
                        txtUsername.IsEnabled = false;
                        txtIPAddress.IsEnabled = false;

                        // Attempt to connect to the server with the provided username and IP
                        MainViewModel._server.ConnectToServer(MainViewModel.Username, txtIPAddress.Text);

                        // Update UI to reflect connected state
                        this.Title += " - Connected to the server.";
                        MainViewModel.IsConnectedToServer = true;
                        cmdConnect.Content = "_Disconnect"; // Button text changes to "Disconnect"

                        // Save last used IP in settings
                        chat_client.Properties.Settings.Default.LastIPAddressUsed = MainViewModel.IPAddressOfServer;
                        chat_client.Properties.Settings.Default.Save();

                        spnCenter.Visibility = Visibility.Visible;
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("The server is unreachable or has refused the connection.", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                        cmdConnect.IsEnabled = true;
                        txtUsername.IsEnabled = true;
                        txtIPAddress.IsEnabled = true;
                        this.Title = "WPF Chat Server";
                        spnCenter.Visibility = Visibility.Hidden;
                    }
                }
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

        private void frmMainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            txtIPAddress.Text = chat_client.Properties.Settings.Default.LastIPAddressUsed;
            
            // Synchronize the toggle button with the current theme
            ThemeToggle.IsChecked = Properties.Settings.Default.AppTheme == "Dark";

            // Attach event handlers to save theme choice when toggled
            ThemeToggle.Checked += (s, _) =>
            {
                // Save dark theme preference
                Properties.Settings.Default.AppTheme = "Dark";
                Properties.Settings.Default.Save();
            };

            ThemeToggle.Unchecked += (s, _) =>
            {
                // Save light theme preference
                Properties.Settings.Default.AppTheme = "Light";
                Properties.Settings.Default.Save();
            };

            txtUsername.Focus();

        }

        private void OnTextBoxTextChanged(object sender, TextChangedEventArgs e)
        {
            if (sender is not TextBox txtbox)
                return;

            // Determine which background resource to use based on TextBox name
            string? resourceKey = txtbox.Name switch
            {
                "txtUsername" => "txtUsername_background",
                "txtIPAddress" => "txtIPAddress_background",
                _ => null
            };

            if (string.IsNullOrEmpty(txtbox.Text))
            {
                if (resourceKey != null)
                {
                    if (TryFindResource(resourceKey) is ImageBrush brush)
                    {
                        txtbox.Background = brush;
                    }
                }
            }
            else
            {
                txtbox.Background = null;
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
                cmdConnect.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
        }

        private void txtMessageToSend_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == Key.Enter && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
            {
                // Simulate the click on the cmdSend button
                cmdSend.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));

                // Prevents the line break in the textBox
                e.Handled = true;
            }
        }

        private void txtMessageToSend_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (txtMessageToSend.Text == "" || MainViewModel.IsConnectedToServer == false)
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
                cmdConnect.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
        }

    }
}