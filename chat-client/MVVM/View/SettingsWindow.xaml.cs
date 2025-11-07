/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 7th, 2025</date>

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
        /// Initializes the settings window by loading and applying saved preferences.
        /// </summary>
        private void SettingsWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // Initialize and apply the saved UI language resources
                var appLanguage = Properties.Settings.Default.AppLanguage;
                LocalizationManager.Initialize(appLanguage);
                LocalizationManager.UpdateLocalizedUI();
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"SettingsWindow_Loaded failed: {ex.Message}", ClientLogLevel.Error);
                MessageBox.Show(
                    LocalizationManager.GetString("ErrorLoadingThemeResources"),
                    LocalizationManager.GetString("Error"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
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
  
        private void UseEncryptionToggle_Checked(object sender, RoutedEventArgs e)
        {
            // Delegate to MainViewModel
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                Properties.Settings.Default.UseEncryption = true;
            }
        }

        private void UseEncryptionToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            // Delegate to MainViewModel
            if (Application.Current.MainWindow is MainWindow mainWindow)
                Properties.Settings.Default.UseEncryption = false;
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
