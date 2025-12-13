/// <file>SettingsWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 13th, 2025</date>

using chat_client.Helpers;                   // For EncryptionHelper, ClientLogger
using chat_client.MVVM.ViewModel;            // For SettingsViewModel
using chat_client.Properties;
using chat_client.View;                      // For AboutWindow
using Hardcodet.Wpf.TaskbarNotification;     // For TaskbarIcon
using System;
using System.ComponentModel;                 // For PropertyChangedEventArgs
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
        // Holds the SettingsViewModel instance for data binding
        private readonly SettingsViewModel _settingsViewModel;

        /// <summary>
        /// Initializes the SettingsWindow with the provided MainViewModel.
        /// </summary>
        public SettingsWindow(MainViewModel mainViewModel)
        {
            InitializeComponent();

            // Creates and assigns DataContext
            _settingsViewModel = new SettingsViewModel(mainViewModel);
            DataContext = _settingsViewModel;

            // Subscribes to property changes
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
                case nameof(SettingsViewModel.ReduceToTray):
                    
                    InitializeTrayIcon();
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

        private void InitializeTrayIcon()
        {
            try
            {
                if (Application.Current.MainWindow is not MainWindow main)
                {
                    return;
                }

                if (main.TryFindResource("TrayIcon") is not TaskbarIcon icon)
                {
                    return;
                }

                main.InitializeTrayIcon();
            }
            catch
            {
            }
        }

        private void ReduceToTrayToggle_Checked(object sender, RoutedEventArgs e)
        {
            Settings.Default.ReduceToTray = true;
            Settings.Default.Save();

            InitializeTrayIcon();
        }

        private void ReduceToTrayToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            Settings.Default.ReduceToTray = false;
            Settings.Default.Save();

            UnloadTrayIcon();
        }

        /// <summary>
        /// Validates the custom port value as the user edits the text, if the custom port option is enabled.
        /// </summary>
        /// <param name="sender">The TextBox whose content has changed.</param>
        /// <param name="e">Event data for the text change.</param>
        private void TxtCustomPort_TextChanged(object sender, TextChangedEventArgs e)
        {
            ValidatePortInput();
        }

        private void UnloadTrayIcon()
        {
            try
            {
                if (Application.Current.MainWindow is not MainWindow main)
                {
                    return;
                }

                if (main.TryFindResource("TrayIcon") is not TaskbarIcon trayIcon)
                {
                    return;
                }

                trayIcon.Dispose();
            }
            catch
            {   
            }
        }

        /// <summary>
        /// If the entered port is invalid, 
        /// silently falls back to 7123 and shows a red dot icon.
        /// </summary>
        private void ValidatePortInput()
        {
            /// <summary> 
            /// If the textbox content is not a valid integer, stop here to avoid
            /// processing invalid data (empty, non‑numeric or whitespace)
            /// </summary> 
            if (!int.TryParse(TxtPort.Text, out int inputPort))
            {
                /// <summary> Invalid value : silently resets the default port </summary> 
                Settings.Default.PortNumber = 7123;
                Settings.Default.Save();

                TxtPort.Text = "7123";

                ImgPortStatus.Source = new BitmapImage(new Uri("/Resources/reddot.png", UriKind.Relative));
                ImgPortStatus.ToolTip = LocalizationManager.GetString("PortNumberInvalid")
                                       + "\n"
                                       + LocalizationManager.GetString("ChooseAnAppropriatePortNumber");

                return;
            }

            bool isPortValid = MainViewModel.TrySavePort(inputPort);

            if (!isPortValid)
            {
                /// <summary> Invalid value : silently resets the default port </summary> 
                Settings.Default.PortNumber = 7123;
                Settings.Default.Save();

                TxtPort.Text = "7123";

                ImgPortStatus.Source = new BitmapImage(new Uri("/Resources/reddot.png", UriKind.Relative));
                ImgPortStatus.ToolTip = LocalizationManager.GetString("PortNumberInvalid")
                                       + "\n"
                                       + LocalizationManager.GetString("ChooseAnAppropriatePortNumber");

                return;
            }

            /// <summary> Valid port : green validate icon </summary> 
            ImgPortStatus.Source = new BitmapImage(new Uri("/Resources/validate.png", UriKind.Relative));
            ImgPortStatus.ToolTip = LocalizationManager.GetString("PortNumberValid");
        }
    }
}
