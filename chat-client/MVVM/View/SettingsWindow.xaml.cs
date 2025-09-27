/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 27th, 2025</date>

using chat_client.Helpers;
using chat_client.MVVM.ViewModel;
using chat_client.View;
using ChatClient.Helpers;
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
                txtCustomPort.Text = MainViewModel.GetCurrentPort().ToString();
                ReduceToTrayToggle.IsChecked = Properties.Settings.Default.ReduceToTray;
                UseEncryptionToggle.IsChecked = chat_client.Properties.Settings.Default.UseEncryption;

                // Initialization complete — toggle events may now fire
                IsInitializing = false;
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
        /// 1. Enables the encryption flag and persists it to user settings.
        /// 2. Clears any stale key material (local and peer) to guarantee a clean start.
        /// 3. Calls InitializeEncryptionFull() on the ViewModel to run the complete RSA generation, publish, and sync pipeline.
        /// 4. If initialization fails, rolls back the toggle and leaves encryption disabled.
        /// 5. Logs success; MainWindow’s PropertyChanged handlers will display the colored lock icon when ready.
        /// </summary>
        private void UseEncryptionToggle_Checked(object sender, RoutedEventArgs e)
        {
            if (IsInitializing)
                return;

            // 1. Enable encryption in settings
            Properties.Settings.Default.UseEncryption = true;
            Properties.Settings.Default.Save();

            // Retrieves the shared ViewModel from MainWindow
            var viewModel = (Application.Current.MainWindow as MainWindow)?._viewModel;
            if (viewModel?.LocalUser == null || !viewModel.IsConnected)
            {
                ClientLogger.Log(
                    "Cannot enable encryption – client not connected or LocalUser missing.",
                    ClientLogLevel.Warn);

                UseEncryptionToggle.IsChecked = false;
                return;
            }

            // 2. Clear previous crypto state
            viewModel.KnownPublicKeys.Clear();
            viewModel.LocalUser.PublicKeyBase64 = string.Empty;
            viewModel.LocalUser.PrivateKeyBase64 = string.Empty;
            EncryptionHelper.ClearPrivateKey();
            ClientLogger.Log(
                "Cleared all old key state before re-initialization.",
                ClientLogLevel.Debug);

            // 3. Run the full E2E encryption initialization pipeline
            bool isReady = viewModel.InitializeEncryptionFull();
            if (!isReady)
            {
                // 4. Roll back on failure
                ClientLogger.Log(
                    "InitializeEncryptionFull() failed – rolling back toggle.",
                    ClientLogLevel.Error);

                UseEncryptionToggle.IsChecked = false;
                Properties.Settings.Default.UseEncryption = false;
                Properties.Settings.Default.Save();
                return;
            }

            // 5. Initialization succeeded; MainWindow will update the lock icon when IsEncryptionReady=true
            ClientLogger.Log("Encryption fully initialized on toggle ON; awaiting green lock icon.",
                ClientLogLevel.Info);
        }

        /// <summary>
        /// Handles the Unchecked event of the encryption toggle.
        /// 1. Disables the encryption flag and persists it to user settings.
        /// 2. Clears all local and peer key material to reset encryption.
        /// 3. Invokes ViewModel.EvaluateEncryptionState() to update IsEncryptionReady/IsEncryptionSyncing.
        /// 4. Relies on MainWindow’s PropertyChanged subscription to update the lock icon accordingly.
        /// </summary>
        private void UseEncryptionToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            if (IsInitializing)
                return;

            // 1. Disables encryption in settings
            Properties.Settings.Default.UseEncryption = false;
            Properties.Settings.Default.Save();

            // 2. Retrieves MainViewModel and ensure LocalUser is initialized;
            //    if MainWindow, ViewModel or LocalUser is null, abort.
            var mainWindow = Application.Current.MainWindow as MainWindow;
            if (mainWindow == null)
                return;
            var viewModel = mainWindow._viewModel;
            if (viewModel?.LocalUser == null)
                return;
            var localUser = viewModel.LocalUser;

            // 3. Clears all encryption state
            EncryptionHelper.ClearPrivateKey();
            localUser.PublicKeyBase64 = string.Empty;
            localUser.PrivateKeyBase64 = string.Empty;
            viewModel.KnownPublicKeys.Clear();

            // 4. Recalculates encryption state (raises PropertyChanged for UI handlers)
            viewModel.EvaluateEncryptionState();
            ClientLogger.Log("Encryption disabled and all keys cleared.", ClientLogLevel.Info);
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
