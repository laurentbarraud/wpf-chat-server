/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 4th, 2025</date>

using System;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using System.ComponentModel;                 // For PropertyChangedEventArgs
using System.Windows;
using Hardcodet.Wpf.TaskbarNotification;     // For TaskbarIcon
using chat_client.MVVM.ViewModel;            // For SettingsViewModel
using chat_client.Helpers;                   // For EncryptionHelper, ClientLogger
using chat_client.View;                      // For AboutWindow


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

        // Holds the SettingsViewModel instance for data binding
        private readonly SettingsViewModel _settingsViewModel;

        public SettingsWindow()
        {
            InitializeComponent();

            // Instantiates SettingsViewModel
            _settingsViewModel = new SettingsViewModel();

            // Assigns SettingsViewModel as DataContext
            DataContext = _settingsViewModel;

            // Subscribes to view-model property changes
            _settingsViewModel.PropertyChanged += SettingsViewModel_PropertyChanged;
        }

        // Handles ReduceToTray property change to update tray icon
        private void SettingsViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            switch (e.PropertyName)
            {
                case nameof(SettingsViewModel.CustomPortNumber):
                    ValidatePortInput();                                       // Validates port and updates image
                    break;

                case nameof(SettingsViewModel.UseCustomPort):
                    ImgPortStatus.Visibility =                                 // Shows/hides status icon
                        _settingsViewModel.UseCustomPort
                        ? Visibility.Visible
                        : Visibility.Collapsed;
                    break;

                case nameof(SettingsViewModel.ReduceToTray):
                    HandleTrayIcon();                                          // Manages tray icon visibility
                    break;
            }
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
                TxtCustomPort.Text = MainViewModel.GetCustomPort().ToString();
                UseEncryptionToggle.IsChecked = chat_client.Properties.Settings.Default.UseEncryption;
            }
            catch (Exception ex)
            {
                // Logs the error to console to help diagnose crashes
                ClientLogger.Log($"SettingsWindow_Loaded failed: {ex.Message}", ClientLogLevel.Error);
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
        /// Initializes or hides the tray icon based on ReduceToTray.
        /// </summary>
        private void HandleTrayIcon()
        {
            var main = Application.Current.MainWindow as MainWindow;
            if (main?.TryFindResource("TrayIcon") is not TaskbarIcon icon)
                return;

            if (_settingsViewModel.ReduceToTray)
            {
                main.EnsureTrayIconReady();                                // Creates tray icon once
            }
            else
            {
                icon.Visibility = Visibility.Collapsed;                    // Hides tray icon
            }
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
            // Updates setting and persists
            Properties.Settings.Default.UseEncryption = true;
            Properties.Settings.Default.Save();

            var main = Application.Current.MainWindow as MainWindow;
            var settingsViewModel = main?.ViewModel;
            if (settingsViewModel?.LocalUser == null || !settingsViewModel.IsConnected)
            {
                ClientLogger.Log("Cannot enable encryption – prerequisites missing.", ClientLogLevel.Warn);
                UseEncryptionToggle.IsChecked = false;
                return;
            }

            // Clears old key state before reinitialization
            settingsViewModel.KnownPublicKeys.Clear();
            settingsViewModel.LocalUser.PublicKeyBase64 = string.Empty;
            settingsViewModel.LocalUser.PrivateKeyBase64 = string.Empty;
            EncryptionHelper.ClearPrivateKey();

            // Executes full encryption setup
            if (!settingsViewModel.InitializeEncryption())
            {
                ClientLogger.Log("Encryption init failed – rolling back.", ClientLogLevel.Error);
                UseEncryptionToggle.IsChecked = false;
            }
            else
            {
                ClientLogger.Log("Encryption initialized successfully.", ClientLogLevel.Info);
            }
        }

        /// <summary>
        /// Handles the Unchecked event of the encryption toggle.
        /// Resets the encryption pipeline by disabling encryption in settings,
        /// clearing all key material, re-evaluating readiness, and hiding the lock icon.
        /// This method showcases a clear, maintainable approach for disabling encryption.
        /// </summary>
        /// <param name="sender">ToggleButton that raised the event.</param>
        /// <param name="e">Event data for the toggle action.</param>
        private void UseEncryptionToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            // Disable encryption in application settings and persist the change
            Properties.Settings.Default.UseEncryption = false;
            Properties.Settings.Default.Save();

            // Retrieve MainViewModel from the main application window
            if (Application.Current.MainWindow is not MainWindow mainWindow
                || mainWindow.ViewModel?.LocalUser == null)
            {
                return;
            }

            var viewModel = mainWindow.ViewModel;

            // Clear local RSA key material from memory
            EncryptionHelper.ClearPrivateKey();
            viewModel.LocalUser.PublicKeyBase64 = string.Empty;
            viewModel.LocalUser.PrivateKeyBase64 = string.Empty;

            // Clear all known peer public keys
            viewModel.KnownPublicKeys.Clear();

            // Re-evaluate encryption readiness (will be false)
            viewModel.EvaluateEncryptionState();
            ClientLogger.Log("Encryption disabled and all keys cleared.", ClientLogLevel.Info);

            // Hide the encryption lock icon to reflect disabled encryption
            Application.Current.Dispatcher.Invoke(() =>
                mainWindow.UpdateEncryptionStatusIcon(false));
        }

        private void ValidatePortInput()
        {
            if (!int.TryParse(TxtCustomPort.Text, out int port)) return;

            bool isValid = MainViewModel.TrySavePort(port);
            var uri = isValid
                      ? new Uri("/Resources/greendot.png", UriKind.Relative)
                      : new Uri("/Resources/reddot.png", UriKind.Relative);

            ImgPortStatus.Source = new BitmapImage(uri);
            ImgPortStatus.ToolTip = isValid
                ? LocalizationManager.GetString("PortNumberValid")
                : LocalizationManager.GetString("PortNumberInvalid")
                  + "\n"
                  + LocalizationManager.GetString("ChooseAnAppropriatePortNumber");
        }
    }
}
