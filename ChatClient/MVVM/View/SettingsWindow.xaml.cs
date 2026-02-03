/// <file>SettingsWindow.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 3rd, 2026</date>

using ChatClient.Helpers;                   // For EncryptionHelper, ClientLogger
using ChatClient.MVVM.ViewModel;   
using ChatClient.Properties;
using Hardcodet.Wpf.TaskbarNotification;     // For TaskbarIcon
using System;
using System.ComponentModel;                 // For PropertyChangedEventArgs
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Imaging;

namespace ChatClient.MVVM.View
{
    /// <summary>
    /// Settings window bound to the main ViewModel.
    /// Allows users to configure client preferences and persists them across sessions.
    /// </summary>
    public partial class SettingsWindow : Window
    {
        private readonly MainViewModel _mainViewModel;

        public SettingsWindow(MainViewModel mainViewModel)
        {
            InitializeComponent();

            _mainViewModel = mainViewModel;
            DataContext = _mainViewModel;

            // Listens to ViewModel property changes (language, tray behavior, etc.)
            _mainViewModel.PropertyChanged += MainViewModel_PropertyChanged;

            // Initial refresh when window opens
            _mainViewModel.LoadLocalizedStrings();
        }

        /// <summary>
        /// Handles property change notifications from MainViewModel.
        /// Updates UI elements in SettingsWindow when specific properties change.
        /// </summary>
        private void MainViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            switch (e.PropertyName)
            {
                case nameof(MainViewModel.ReduceToTray):
                    InitializeTrayIcon();
                    break;

                case nameof(MainViewModel.AppLanguage):
                    RefreshLocalizedBindings();
                    break;
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

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private void ReduceToTrayToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            Settings.Default.ReduceToTray = false;
            Settings.Default.Save();

            UnloadTrayIcon();
        }

        /// <summary>
        /// Updates all localized bindings in the settings window.
        /// Ensures labels and tooltips refresh immediately when the language changes.
        /// </summary>
        private void RefreshLocalizedBindings()
        {
            UpdateBinding(UseTcpPortLabel);
            UpdateBinding(ReduceToTrayLabel);
            UpdateBinding(UseEncryptionLabel);
            UpdateBinding(DisplayFontSizeLabel);
            UpdateBinding(MessageInputFieldWidthLabel);
            UpdateBinding(MessageInputFieldLeftOffsetLabel);
            UpdateBinding(AppLanguageLabel);
            UpdateBinding(AboutLabel);
        }

        /// <summary>
        /// Validates the custom port value as the user edits the text, if the custom port option is enabled.
        /// </summary>
        /// <param name="sender">The TextBox whose content has changed.</param>
        /// <param name="e">Event data for the text change.</param>
        private void TxtPort_TextChanged(object sender, TextChangedEventArgs e)
        {
            ValidatePortInput();
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static void UnloadTrayIcon()
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

                trayIcon?.Dispose();
            }
            catch
            {   
            }
        }

        /// <summary>
        /// Forces WPF to re-evaluate the Content binding of a control.
        /// </summary>
        private static void UpdateBinding(ContentControl control)
        {
            control.GetBindingExpression(ContentControl.ContentProperty)?.UpdateTarget();
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

                ImgPortStatus.Source = new BitmapImage(new Uri("/Resources/invalid.png", UriKind.Relative));
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

                ImgPortStatus.Source = new BitmapImage(new Uri("/Resources/invalid.png", UriKind.Relative));
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
