/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 9th, 2025</date>

using chat_client.Helpers;
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

        private void SettingsWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Retrieve saved language from application settings
            string AppLanguageSaved = Properties.Settings.Default.AppLanguage;

            // Initialize the localization manager with the saved language
            LocalizationManager.Initialize(AppLanguageSaved);

            // Select the corresponding ComboBox item based on the saved language
            foreach (ComboBoxItem item in LanguageComboBox.Items)
            {
                if ((string)item.Tag == AppLanguageSaved)
                {
                    LanguageComboBox.SelectedItem = item;
                    break;
                }
            }

            // Apply localized strings to UI elements
            UpdateUIStrings();

            // Synchronize toggle buttons and port field with saved settings
            UseCustomPortToggle.IsChecked = Properties.Settings.Default.UseCustomPort;
            txtCustomPort.Text = MainViewModel.GetCurrentPort().ToString();
            ReduceInTrayToggle.IsChecked = Properties.Settings.Default.ReduceInTray;
            UseEncryptionToggle.IsChecked = Properties.Settings.Default.UseEncryption;
        }

        private void AboutLabel_MouseDown(object sender, MouseButtonEventArgs e)
        {
            MessageBox.Show(
            "This software is for education purposes only and is provided \"as is\", without any kind of warranty.\n" +
            "In no event shall the author be liable for any indirect, incidental or consequential damages, " +
            "including loss of data, lost profits, or business interruption " +
            "with the use of this software.\n" +
            "Button images inspired by resources available on flaticon.com.\n\n" +
            "v1.0, sept. 2025 — by Laurent Barraud.",
            "About",
            MessageBoxButton.OK,
            MessageBoxImage.Information
            );
        }

        private void btnValidate_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        /// <summary>
        /// Handles language selection change from the ComboBox.
        /// Updates the application language only if the selected language is different,
        /// then reinitializes localization and refreshes UI texts.
        /// </summary>
        private void LanguageComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (LanguageComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                // Get the newly selected language code
                string selectedLang = (string)selectedItem.Tag;

                // Get the currently saved language
                string AppLanguageSaved = Properties.Settings.Default.AppLanguage;

                // Only proceed if the selected language is different from the saved one
                if (selectedLang != AppLanguageSaved)
                {
                    // Save the new language to application settings
                    Properties.Settings.Default.AppLanguage = selectedLang;
                    Properties.Settings.Default.Save();

                    // Reinitialize localization manager with the new language
                    LocalizationManager.Initialize(selectedLang);

                    // Refresh all UI labels and texts with localized strings
                    UpdateUIStrings();
                }
            }
        }

        private void ReduceInTrayToggle_Checked(object sender, RoutedEventArgs e)
        {
            Properties.Settings.Default.ReduceInTray = true;
            Properties.Settings.Default.Save();
        }

        private void ReduceInTrayToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            Properties.Settings.Default.ReduceInTray = false;
            Properties.Settings.Default.Save();
        }


        private void txtCustomPort_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (UseCustomPortToggle.IsChecked == true)
            {
                ValidatePortInput();
            }
        }

        /// <summary>
        /// Updates all visible UI elements with localized strings
        /// based on the current language set in the localization manager.
        /// </summary>
        private void UpdateUIStrings()
        {
            // Settings window
            UseCustomPortLabel.Content = LocalizationManager.GetString("UseCustomPortLabel");
            ReduceInTrayLabel.Content = LocalizationManager.GetString("ReduceInTrayLabel");
            UseEncryptionLabel.Content = LocalizationManager.GetString("UseEncryptionLabel");
            AppLanguageLabel.Content = LocalizationManager.GetString("AppLanguageLabel");
        
            // Main window

        }


        private void UseCustomPortToggle_Checked(object sender, RoutedEventArgs e)
        {
            txtCustomPort.IsEnabled = true;
            Properties.Settings.Default.UseCustomPort = true;
            Properties.Settings.Default.Save();

            // Shows the encryption icon
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                mainWindow.imgEncryptionStatus.Visibility = Visibility.Visible;
            }
        }

        private void UseCustomPortToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            txtCustomPort.IsEnabled = false;
            imgPortStatus.Visibility = Visibility.Collapsed;
            Properties.Settings.Default.UseCustomPort = false;
            Properties.Settings.Default.Save();

            // Hides the encryption icon
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                mainWindow.imgEncryptionStatus.Visibility = Visibility.Collapsed;
            }
        }

        private void UseEncryptionToggle_Checked(object sender, RoutedEventArgs e)
        {
            Properties.Settings.Default.UseEncryption = true;
            Properties.Settings.Default.Save();

            // Shows the encryption icon in MainWindow
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                mainWindow.imgEncryptionStatus.Visibility = Visibility.Visible;
            }
        }

        private void UseEncryptionToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            Properties.Settings.Default.UseEncryption = false;
            Properties.Settings.Default.Save();

            // Hides the encryption icon in MainWindow
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                mainWindow.imgEncryptionStatus.Visibility = Visibility.Collapsed;
            }
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
