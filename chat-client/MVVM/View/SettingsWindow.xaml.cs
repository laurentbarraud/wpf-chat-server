/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 16th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.Net;
using chat_client.Net.IO;
using Hardcodet.Wpf.TaskbarNotification;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Policy;
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
            try
            {
                // Retrieves saved language from application settings
                string appLanguage = Properties.Settings.Default.AppLanguage;

                // Initializes the localization manager with the saved language
                 LocalizationManager.Initialize(appLanguage);

                // Refreshes all UI labels and texts with localized strings
                LocalizationManager.UpdateLocalizedUI();

                // Selects the corresponding ComboBox item based on the saved app language
                foreach (ComboBoxItem item in LanguageComboBox.Items)
                {
                    if ((string)item.Tag == appLanguage)
                    {
                        LanguageComboBox.SelectedItem = item;
                        break;
                    }
                }

                // Synchronizes toggles states and port field with saved settings
                UseCustomPortToggle.IsChecked = Properties.Settings.Default.UseCustomPort;
                txtCustomPort.Text = MainViewModel.GetCurrentPort().ToString();

                ReduceToTrayToggle.IsChecked = chat_client.Properties.Settings.Default.ReduceToTray;
                
                UseEncryptionToggle.IsChecked = Properties.Settings.Default.UseEncryption;
            }
            catch (Exception ex)
            {
                // Logs the error to console to help diagnose crashes
                Console.WriteLine($"[ERROR] SettingsWindow_Loaded failed: {ex.Message}");
                MessageBox.Show(LocalizationManager.GetString("ErrorLoadingThemeResources"), LocalizationManager.GetString("Error"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void AboutLabel_MouseDown(object sender, MouseButtonEventArgs e)
        {
            MessageBox.Show(
            LocalizationManager.GetString("LicenceInfo1") + "\n" +
            LocalizationManager.GetString("LicenceInfo2") + "\n" +
            LocalizationManager.GetString("LicenceInfoResources") + "\n\n" +
            LocalizationManager.GetString("LicenceFinal"),
            LocalizationManager.GetString("About"),
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
                string languageCodeSelected = selectedItem.Tag.ToString(); // "en" or "fr"

                // Get the currently saved language
                string AppLanguageSaved = Properties.Settings.Default.AppLanguage;

                // Only proceed if the selected language is different from the saved one
                if (languageCodeSelected != AppLanguageSaved)
                {
                    // Save the new language to application settings
                    Properties.Settings.Default.AppLanguage = languageCodeSelected;
                    Properties.Settings.Default.Save();

                    // Reinitialize localization manager with the new language
                    LocalizationManager.Initialize(languageCodeSelected);
                }
            }
        }

        /// <summary>
        /// Triggered when the "Reduce to Tray" toggle is checked.
        /// Updates the application setting and ensures the tray icon is initialized only if not already visible.
        /// Prevents redundant initialization and visual flickering.
        /// </summary>
        private void ReduceToTrayToggle_Checked(object sender, RoutedEventArgs e)
        {
            chat_client.Properties.Settings.Default.ReduceToTray = true;
            chat_client.Properties.Settings.Default.Save();

            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                var trayIcon = mainWindow.TryFindResource("TrayIcon") as TaskbarIcon;

                // Only initialize if tray icon is not already visible
                if (trayIcon != null)
                {
                    mainWindow.EnsureTrayIconReady();
                }
            }
        }

        /// <summary>
        /// Triggered when the "Reduce to Tray" toggle is unchecked.
        /// Updates the application setting and hides the tray icon if active.
        /// Disables tray-based minimization behavior until re-enabled.
        /// </summary>
        private void ReduceToTrayToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            chat_client.Properties.Settings.Default.ReduceToTray = false;
            chat_client.Properties.Settings.Default.Save();

            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                var trayIcon = mainWindow.TryFindResource("TrayIcon") as TaskbarIcon;
                if (trayIcon != null)
                {
                    trayIcon.Visibility = Visibility.Collapsed;
                }
            }
        }

        /// <summary>
        /// Applies the user's intent to enable or disable encryption.
        /// Handles key generation, transmission, rollback on failure, and UI updates.
        /// Ensures idempotent behavior and avoids duplicate key transmission.
        /// Returns true if the toggle was successfully applied; otherwise, false.
        /// </summary>
        private bool TryApplyEncryptionToggle(bool shouldEnableEncryption)
        {
            var viewModel = (Application.Current.MainWindow as MainWindow)?.ViewModel;
            if (viewModel == null)
                return false;

            if (shouldEnableEncryption)
            {
                // Persist the user's intent to enable encryption
                Properties.Settings.Default.UseEncryption = true;
                Properties.Settings.Default.Save();

                // If the client is connected and LocalUser is initialized, attempt encryption setup
                if (viewModel.LocalUser != null && viewModel.IsConnected)
                {
                    // Try to initialize encryption: generate RSA keys and send public key to server
                    bool encryptionInitialized = viewModel.InitializeEncryptionIfEnabled();

                    if (!encryptionInitialized)
                    {
                        // Setup failed (e.g. socket issue, handshake incomplete)
                        // Do NOT rollback the toggle — user intent is preserved
                        Console.WriteLine("[WARN] Encryption setup failed. Will retry after connection.");
                    }
                }
                else
                {
                    // Not connected yet — defer encryption setup until connection is established
                    Console.WriteLine("[INFO] Encryption enabled. Waiting for connection to initialize.");
                }

                // Update encryption icon to reflect current state (may be grayed out if keys not exchanged)
                viewModel.EnsureEncryptionReady();
                return true;
            }
            else
            {
                // User intends to disable encryption — reset all related state
                Properties.Settings.Default.UseEncryption = false;
                Properties.Settings.Default.Save();

                // Clear local key only if LocalUser exists
                if (viewModel.LocalUser != null)
                {
                    viewModel.LocalUser.PublicKeyBase64 = null;
                }

                // Clear key exchange state
                viewModel.KnownPublicKeys.Clear();
                viewModel.SentKeys.Clear();

                // Update encryption icon to reflect disabled state
                viewModel.EnsureEncryptionReady();

                Console.WriteLine("[INFO] Encryption disabled and reset.");
                return true;
            }
        }


        private void txtCustomPort_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (UseCustomPortToggle.IsChecked == true)
            {
                ValidatePortInput();
            }
        }

        private void UseCustomPortToggle_Checked(object sender, RoutedEventArgs e)
        {
            txtCustomPort.IsEnabled = true;
            Properties.Settings.Default.UseCustomPort = true;
            Properties.Settings.Default.Save();
        }

        private void UseCustomPortToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            txtCustomPort.IsEnabled = false;
            imgPortStatus.Visibility = Visibility.Collapsed;
            Properties.Settings.Default.UseCustomPort = false;
            Properties.Settings.Default.Save();
        }

        /// <summary>
        /// Handles the Checked event of the encryption toggle.
        /// Delegates to TryApplyEncryptionToggle(true) to initialize encryption if prerequisites are met.
        /// Rolls back the toggle if encryption setup fails.
        /// </summary>
        private void UseEncryptionToggle_Checked(object sender, RoutedEventArgs e)
        {
            bool toggleSucceeded = TryApplyEncryptionToggle(shouldEnableEncryption: true);

            if (!toggleSucceeded)
            {
                // Revert toggle visually if encryption setup failed
                UseEncryptionToggle.IsChecked = false;
                Console.WriteLine("[INFO] Encryption toggle reverted due to setup failure.");
            }
        }

        /// <summary>
        /// Handles the Unchecked event of the encryption toggle.
        /// Delegates to TryApplyEncryptionToggle(false) to disable encryption and reset state.
        /// </summary>
        private void UseEncryptionToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            TryApplyEncryptionToggle(shouldEnableEncryption: false);
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
                tooltip = LocalizationManager.GetString("PortNumberValid");
            }
            else
            {
                imagePath = "/Resources/reddot.png";
                tooltip = LocalizationManager.GetString("PortNumberInvalid") + "\n" + LocalizationManager.GetString("ChooseAnAppropriatePortNumber");
            }

            imgPortStatus.Source = new BitmapImage(new Uri(imagePath, UriKind.Relative));
            imgPortStatus.ToolTip = tooltip;
            imgPortStatus.Visibility = Visibility.Visible;
        }
    }
}
