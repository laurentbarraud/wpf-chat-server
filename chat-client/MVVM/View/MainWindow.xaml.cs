/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.7</version>
/// <date>September 3rd, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.Net;
using System.Configuration;
using System.Net.Sockets;
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
        }


        public void cmdConnectDisconnect_Click(object sender, RoutedEventArgs e)
        {
            ViewModel.ConnectDisconnect();
        }

        private void cmdPortSetting_Click(object sender, RoutedEventArgs e)
        {
            ShowPortSetting();
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

        private void cmdValidatePort_Click(object sender, RoutedEventArgs e)
        {
            ValidatePortInput();
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
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
        public void ShowPortSetting()
        {
            if (popupPort.IsOpen)
            {
                popupPort.IsOpen = false;

            }
            else
            {
                popupPort.IsOpen = true;
                txtPortPopup.Text = ViewModel.GetCurrentPort().ToString();
                txtPortPopup.Focus();
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

        private void txtPortPopup_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                ValidatePortInput();
            }
        }

        private void txtPortPopup_LostFocus(object sender, RoutedEventArgs e)
        {
            // Close silently without saving changes
            popupPort.IsOpen = false;
        }

        private void ValidatePortInput()
        {
            int portChosen;
            Int32.TryParse(txtPortPopup.Text, out portChosen);

            string imagePath;
            string tooltip;

            if (ViewModel.TrySavePort(portChosen))
            {
                imagePath = "/Resources/greendot.png";
                tooltip = "Port number is valid.";
            }
            else
            {
                imagePath = "/Resources/reddot.png";
                tooltip = "Port number is not valid.\nPlease choose a number between 1000 and 65535.";

                txtPortPopup.Text = ViewModel.GetCurrentPort().ToString();
                txtPortPopup.Focus();
            }

            imgPortStatus.Source = new BitmapImage(new Uri(imagePath, UriKind.Relative));
            imgPortStatus.ToolTip = tooltip;
            imgPortStatus.Visibility = Visibility.Visible;
        }
    }
}