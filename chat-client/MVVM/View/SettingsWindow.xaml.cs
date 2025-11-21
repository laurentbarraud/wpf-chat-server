/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 21th, 2025</date>

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
        // Holds the SettingsViewModel instance for data binding
        private readonly SettingsViewModel _settingsViewModel;

        /// <summary>
        /// Initializes the SettingsWindow.
        /// Creates a SettingsViewModel instance bound to the provided MainViewModel,
        /// assigns it as the DataContext for XAML bindings,
        /// and subscribes to property changes to react to user preferences
        /// such as encryption, custom port, and tray behavior.
        /// </summary>
        public SettingsWindow(MainViewModel mainViewModel)
        {
            InitializeComponent();

            // Instantiates SettingsViewModel with a reference to MainViewModel
            _settingsViewModel = new SettingsViewModel(mainViewModel);

            // Assigns SettingsViewModel as DataContext, so that all the properties become accessible in XAML via {Binding ...}
            DataContext = _settingsViewModel;

            // Subscribes once to PropertyChanged; handler reacts to multiple changes
            _settingsViewModel.PropertyChanged += SettingsViewModel_PropertyChanged;
        }

        /// <summary>
        /// Handles property change notifications from SettingsViewModel.
        /// Updates UI elements in SettingsWindow when specific properties change.
        /// </summary>
        /// <param name="sender">The SettingsViewModel instance raising the event.</param>
        /// <param name="e">Provides the name of the property that changed.</param>
        private void SettingsViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            switch (e.PropertyName)
            {
                case nameof(SettingsViewModel.CustomPortNumber):
                    // Validates port and updates image
                    ValidatePortInput();                                       
                    break;

                case nameof(SettingsViewModel.UseCustomPort):
                    // Shows/hides status icon
                    ImgPortStatus.Visibility = _settingsViewModel.UseCustomPort
                        ? Visibility.Visible
                        : Visibility.Collapsed;
                    break;

                case nameof(SettingsViewModel.ReduceToTray):
                    // Manages tray icon visibility
                    HandleTrayIcon();
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
