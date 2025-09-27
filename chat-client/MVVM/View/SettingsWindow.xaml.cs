/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 28th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.View;
using Hardcodet.Wpf.TaskbarNotification;
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Imaging;

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
        public MainViewModel? ViewModel { get; set; }

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
                TxtCustomPort.Text = MainViewModel.GetCurrentPort().ToString();
                ReduceToTrayToggle.IsChecked = Properties.Settings.Default.ReduceToTray;
                UseEncryptionToggle.IsChecked = chat_client.Properties.Settings.Default.UseEncryption;

                // Initialization complete — toggle events may now fire
                IsInitializing = false;
            }
            catch (Exception ex)
            {
                // Logs the error to console to help diagnose crashes
                ClientLogger.ClientLog($"SettingsWindow_Loaded failed: {ex.Message}", ClientLogLevel.Error);
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

        private void CmdValidate_Click(object sender, RoutedEventArgs e)
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
            if (LanguageComboBox.SelectedItem is ComboBoxItem selectedItem && selectedItem.Tag is string languageCodeSelected)
            {
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
        /// Rolls back the encryption toggle when initialization fails.  
        /// Unchecks the encryption toggle.  
        /// Disables the encryption flag in user settings.  
        /// Persists the change to application settings.  
        /// This method centralizes rollback logic to maintain UI and configuration consistency.
        /// </summary>
        private void RollbackEncryptionToggle()
        {
            UseEncryptionToggle.IsChecked = false;
            Properties.Settings.Default.UseEncryption = false;
            Properties.Settings.Default.Save();
        }

        /// <summary>
        /// Validates the custom port value as the user edits the text, if the custom port option is enabled.
        /// </summary>
        /// <param name="sender">The TextBox whose content has changed.</param>
        /// <param name="e">Event data for the text change.</param>
        private void TxtCustomPort_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (UseCustomPortToggle.IsChecked == true)
            {
                ValidatePortInput();
            }
        }

        /// <summary>
        /// Enables the custom port input field and persists the setting when the toggle is checked.
        /// </summary>
        /// <param name="sender">The toggle button that was checked.</param>
        /// <param name="e">Event data for the toggle event.</param>
        private void UseCustomPortToggle_Checked(object sender, RoutedEventArgs e)
        {
            TxtCustomPort.IsEnabled = true;
            Properties.Settings.Default.UseCustomPort = true;
            Properties.Settings.Default.Save();
        }

        /// <summary>
        /// Disables the custom port input field, hides the status indicator, and persists the setting when the toggle is unchecked.
        /// </summary>
        /// <param name="sender">The toggle button that was unchecked.</param>
        /// <param name="e">Event data for the toggle event.</param>
        private void UseCustomPortToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            TxtCustomPort.IsEnabled = false;
            ImgPortStatus.Visibility = Visibility.Collapsed;
            Properties.Settings.Default.UseCustomPort = false;
            Properties.Settings.Default.Save();
        }

        /// <summary>
        /// Handles the Checked event of the encryption toggle.  
        /// Enables the encryption flag in user settings and persists it.  
        /// Validates that the client is connected and LocalUser is initialized.  
        /// Clears stale key material to guarantee a clean start.  
        /// Invokes ViewModel.InitializeEncryption() to execute the full encryption setup.  
        /// Rolls back the toggle and settings on failure.  
        /// Logs the successful initialization and awaits UI update.  
        /// </summary>
        private void UseEncryptionToggle_Checked(object sender, RoutedEventArgs e)
        {
            if (IsInitializing)
            {
                return;
            }

            // Enables the encryption flag and persists it
            Properties.Settings.Default.UseEncryption = true;
            Properties.Settings.Default.Save();

            // Validates that the client is connected and LocalUser is initialized
            var mainWindow = Application.Current.MainWindow as MainWindow;
            var viewModel = mainWindow?.ViewModel;
            if (viewModel?.LocalUser == null || !viewModel.IsConnected)
            {
                ClientLogger.ClientLog("Cannot enable encryption – client not connected or LocalUser missing.", ClientLogLevel.Warn);
                RollbackEncryptionToggle();
                return;
            }

            // Clears stale key material to guarantee a clean start
            viewModel.KnownPublicKeys.Clear();
            viewModel.LocalUser.PublicKeyBase64 = string.Empty;
            viewModel.LocalUser.PrivateKeyBase64 = string.Empty;
            EncryptionHelper.ClearPrivateKey();
            ClientLogger.ClientLog(
                "Clears old key state before re-initialization.", ClientLogLevel.Debug);

            // Executes full encryption setup and captures the result
            bool isEncryptionReady = viewModel.InitializeEncryption();
            if (!isEncryptionReady)
            {
                // Rolls back the toggle and settings on failure
                ClientLogger.ClientLog("InitializeEncryption() failed – rolling back encryption toggle.", ClientLogLevel.Error);
                RollbackEncryptionToggle();
                return;
            }

            // Logs the successful initialization and awaits UI update
            ClientLogger.ClientLog("Encryption fully initialized on toggle ON; awaiting green lock icon.", ClientLogLevel.Info);
        }

        /// <summary>
        /// Handles the Unchecked event of the encryption toggle.
        /// 1. Disables the encryption flag and persists it to user settings.  
        /// 2. Clears all local and peer key material to reset encryption.  
        /// 3. Invokes ViewModel.EvaluateEncryptionState() to update readiness.  
        /// 4. Logs the outcome; MainWindow’s PropertyChanged subscription will update the lock icon accordingly.  
        /// </summary>
        private void UseEncryptionToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            if (IsInitializing)
            {
                return;
            }

            // 1. Disables the encryption flag in settings and persists it
            Properties.Settings.Default.UseEncryption = false;
            Properties.Settings.Default.Save();

            // 2. Retrieves the MainViewModel and verifies LocalUser initialization
            var mainWindow = Application.Current.MainWindow as MainWindow;
            
            if (mainWindow == null)
            {
                return;
            }
            
            var viewModel = mainWindow.ViewModel;
            
            if (viewModel?.LocalUser == null)
            {
                return;
            }

            var localUser = viewModel.LocalUser;

            // 3. Clears all local and peer key material to reset encryption
            EncryptionHelper.ClearPrivateKey();
            localUser.PublicKeyBase64 = string.Empty;
            localUser.PrivateKeyBase64 = string.Empty;
            viewModel.KnownPublicKeys.Clear();

            // 4. Invokes ViewModel.EvaluateEncryptionState() to update readiness
            viewModel.EvaluateEncryptionState();
            ClientLogger.ClientLog("Encryption disabled and all keys cleared.", ClientLogLevel.Info);
        }
        private void ValidatePortInput()
        {
            int portChosen;
            Int32.TryParse(TxtCustomPort.Text, out portChosen);

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

            ImgPortStatus.Source = new BitmapImage(new Uri(imagePath, UriKind.Relative));
            ImgPortStatus.ToolTip = tooltip;
            ImgPortStatus.Visibility = Visibility.Visible;
        }
    }
}
