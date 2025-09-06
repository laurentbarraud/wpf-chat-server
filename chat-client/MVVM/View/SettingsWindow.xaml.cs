/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.8</version>
/// <date>September 7th, 2025</date>

using chat_client.MVVM.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace chat_client.MVVM.View
{
    /// <summary>
    /// Logique d'interaction pour Settings.xaml
    /// </summary>
    public partial class SettingsWindow : Window
    {
        public MainViewModel ViewModel { get; set; }

        public SettingsWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Synchronizes the toggle button with the "use custom port" setting
            UseCustomPortToggle.IsChecked = Properties.Settings.Default.UseCustomPort e;
        }

        private void AboutLabel_MouseDown(object sender, MouseButtonEventArgs e)
        {
            MessageBox.Show(
            "This software is for education purposes only and is provided \"as is\", without any kind of warranty.\n" +
            "In no event shall the author be liable for any indirect, incidental or consequential damages, " +
            "including loss of data, lost profits, or business interruption " +
            "with the use of the software.\n\n" +
            "Button images inspired by resources on flaticon.com.\n\n" +
            "v0.8, sept. 2025 — by Laurent Barraud.",
            "About",
            MessageBoxButton.OK,
            MessageBoxImage.Information
            );
        }

        private void PortSettingToggle_Checked(object sender, RoutedEventArgs e)
        {
            txtCustomPort.IsEnabled = true;
            txtCustomPort.Text = MainViewModel.GetCurrentPort().ToString();
            Properties.Settings.Default.UseCustomPort = true;
        }

        private void PortSettingToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            txtCustomPort.IsEnabled = false;
            imgPortStatus.Visibility = Visibility.Collapsed;
            Properties.Settings.Default.UseCustomPort = false;
        }

        private void TrayToggle_Checked(object sender, RoutedEventArgs e)
        {

        }

        private void TrayToggle_Unchecked(object sender, RoutedEventArgs e)
        {

        }

        private void txtCustomPort_TextChanged(object sender, TextChangedEventArgs e)
        {
            ValidatePortInput();
        }

        private void ValidatePortInput()
        {
            int portChosen;
            Int32.TryParse(txtCustomPort.Text, out portChosen);

            string imagePath;
            string tooltip;

            if (MainViewModel.TrySavePort(portChosen))
            {
                imagePath = "/Resources/greendot.png";
                tooltip = "Port number is valid.";
            }
            else
            {
                imagePath = "/Resources/reddot.png";
                tooltip = "Port number is not valid.\nPlease choose a number between 1000 and 65535.";
            }

            imgPortStatus.Source = new BitmapImage(new Uri(imagePath, UriKind.Relative));
            imgPortStatus.ToolTip = tooltip;
            imgPortStatus.Visibility = Visibility.Visible;
        }
    }
}
