/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 25th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.Net;
using chat_client.Net.IO;
using chat_client.View;
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
    /// Configuration window for client preferences.
    /// Allows users to customize encryption usage, port settings, and server IP address.
    /// Persists settings across sessions using application-level storage.
    /// Provides localized labels and tooltips for accessibility and clarity.
    /// </summary>
    public partial class SettingsWindow : Window
    {
        public MainViewModel ViewModel { get; set; }

        private bool IsInitializing = true;

        public SettingsWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Initializes the settings window by synchronizing UI controls with saved application preferences.
        /// Loads localization, port configuration, tray behavior, and encryption state.
        /// Ensures that toggle events do not fire during initial binding.
        /// This method guarantees an idempotent UI state for user interaction.
        /// </summary>
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

                // Synchronizes toggle states and port field with saved settings
                UseCustomPortToggle.IsChecked = Properties.Settings.Default.UseCustomPort;
                txtCustomPort.Text = MainViewModel.GetCurrentPort().ToString();
                ReduceToTrayToggle.IsChecked = Properties.Settings.Default.ReduceToTray;
                UseEncryptionToggle.IsChecked = chat_client.Properties.Settings.Default.UseEncryption;

                // Initialization complete — toggle events may now fire
                IsInitializing = false;
            }
            catch (Exception ex)
            {
                // Logs the error to console to help diagnose crashes
                Console.WriteLine($"[ERROR] SettingsWindow_Loaded failed: {ex.Message}");
                MessageBox.Show(LocalizationManager.GetString("ErrorLoadingThemeResources"), LocalizationManager.GetString("Error"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Handles mouse click on the About label.
        /// Opens the AboutWindow as a modal dialog, blocking interaction with the main window until closed.
        /// Ensures the AboutWindow is properly owned by the main application window for focus and stacking.
        /// </summary>
        private void AboutLabel_MouseDown(object sender, MouseButtonEventArgs e)
        {
            var aboutWindow = new AboutWindow();
            aboutWindow.Owner = Application.Current.MainWindow;
            aboutWindow.ShowDialog();
        }

        private void cmdValidate_Click(object sender, RoutedEventArgs e)
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
        /// Attempts to initialize encryption and updates UI accordingly.
        /// Saves the preference only if initialization succeeds.
        /// </summary>
        private void UseEncryptionToggle_Checked(object sender, RoutedEventArgs e)
        {
            if (IsInitializing) return;

            var mainWindow = Application.Current.MainWindow as MainWindow;
            var viewModel = mainWindow?.ViewModel;

            if (viewModel?.LocalUser != null && viewModel.IsConnected)
            {
                bool encryptionInitialized = viewModel.InitializeEncryption(viewModel);

                if (!encryptionInitialized)
                {
                    // Rollbacks toggle immediately — preference will not be saved
                    UseEncryptionToggle.IsChecked = false;
                }
                else
                {
                    // Forces UI update of encryption icon
                    mainWindow?.UpdateEncryptionStatusIcon(viewModel.IsEncryptionReady);

                    // Saves the encryption preference after successful initialization
                    Properties.Settings.Default.UseEncryption = true;
                    Properties.Settings.Default.Save();
                }
            }
        }

        /// <summary>
        /// Handles the Unchecked event of the encryption toggle.
        /// Disables encryption and resets encryption-related state.
        /// Saves the preference immediately.
        /// </summary>
        private void UseEncryptionToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            if (IsInitializing) return;

            Properties.Settings.Default.UseEncryption = false;
            Properties.Settings.Default.Save();

            var viewModel = (Application.Current.MainWindow as MainWindow)?.ViewModel;

            if (viewModel != null)
            {
                viewModel.IsEncryptionReady = false;

                // Clears keys only if LocalUser is initialized and keys are present
                if (viewModel.LocalUser != null &&
                    (!string.IsNullOrEmpty(viewModel.LocalUser.PublicKeyBase64) ||
                     !string.IsNullOrEmpty(viewModel.LocalUser.PrivateKeyBase64)))
                {
                    viewModel.LocalUser.PublicKeyBase64 = null;
                    viewModel.LocalUser.PrivateKeyBase64 = null;
                    EncryptionHelper.ClearPrivateKey();
                }

                viewModel.EvaluateEncryptionState();
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
