/// <file>SettingsWindow.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>July 9th, 2026</date>

using ChatClient.Helpers;               
using ChatClient.Properties;
using Hardcodet.Wpf.TaskbarNotification;
using System;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;

namespace ChatClient.MVVM.View
{
    /// <summary>
    /// Settings window bound to the global view model.
    /// Allows users to configure client preferences and persists them across sessions.
    /// </summary>
    public partial class SettingsWindow : Window
    {
        public SettingsWindow()
        {
            InitializeComponent();

            this.DataContext = App.ViewModel;

            // Listens for ViewModel changes
            App.ViewModel.PropertyChanged += MainViewModel_PropertyChanged;

            App.ViewModel.LoadLocalizedStrings();

            // Clean unsubscribes when window closes.
            // This avoids memory leaks and double refreshes
            // when reopening the settings window multiple times.
            Closed += (_, __) =>
            {
                App.ViewModel.PropertyChanged -= MainViewModel_PropertyChanged;
            };

            // User starts interacting: show popup immediately
            HueSlider.PreviewMouseDown += (_, __) =>
            {
                App.ViewModel.IsHuePopupVisible = true;
                
                if (HuePopupContent != null)
                {
                    // Cancels any previous animation and ensures full opacity
                    HuePopupContent.BeginAnimation(UIElement.OpacityProperty, null);
                    HuePopupContent.Opacity = 1.0;
                }
            };

            // User stops interacting: start delayed fade-out
            HueSlider.PreviewMouseUp += (_, __) =>
            {
                StartHuePopupFadeOutWithDelay();
            };
        }

        /// <summary>
        /// Reacts to global ViewModel changes.
        /// Refreshes localized bindings when the application language changes.
        /// </summary>
        private void MainViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(App.ViewModel.AppLanguage))
            {
                RefreshLocalizedBindings();
                (App.Current.MainWindow as MainWindow)?.UpdateConnectedUsersLabelText();
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

        private void ReduceToTrayToggle_Checked(object sender, RoutedEventArgs e)
        {
            Settings.Default.ReduceToTray = true;
            Settings.Default.Save();
        }

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
            UpdateBinding(EncryptMessagesLabel);
            UpdateBinding(DisplayFontSizeLabel);
            UpdateBinding(MessageInputFieldWidthLabel);
            UpdateBinding(MessageInputFieldLeftOffsetLabel);
            UpdateBinding(AppLanguageLabel);
            UpdateBinding(AboutLabel);

            // Updates the connected users list label
            App.ViewModel.ConnectedUsersListLabelText =
                LocalizationManager.GetString("ConnectedUsersListLabelText");

            // Update IP display if connected
            if (App.ViewModel.IsConnected)
            {
                App.ViewModel.CurrentIPDisplay = $"– {LocalizationManager.GetString("Connected")} –";
            }
        }

        /// <summary>
        /// Starts a delayed fade-out animation on the hue popup.
        /// The popup stays fully visible during interaction, then fades out
        /// after a short inactivity delay.
        /// </summary>
        private void StartHuePopupFadeOutWithDelay()
        {
            if (HuePopupContent == null)
            {
                return;
            }

            var fadeAnimation = new DoubleAnimation
            {
                From = 1.0,
                To = 0.0,
                Duration = TimeSpan.FromMilliseconds(500),
                BeginTime = TimeSpan.FromSeconds(1.5) // delay before fade-out
            };

            fadeAnimation.Completed += (_, __) =>
            {
                // Resets opacity for the next interaction cycle
                HuePopupContent.Opacity = 1.0;

                // Hides popup in the global ViewModel once the fade-out completes
                App.ViewModel.IsHuePopupVisible = false;
            };

            HuePopupContent.BeginAnimation(UIElement.OpacityProperty, fadeAnimation);
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
            // If the textbox content is not a valid integer, stop here to avoid
            // processing invalid data (empty, non‑numeric or whitespace)
            if (!int.TryParse(TxtPort.Text, out int inputPort))
            {
                // Invalid value : silently resets the default port
                Settings.Default.PortNumber = 7123;
                Settings.Default.Save();

                TxtPort.Text = "7123";

                ImgPortStatus.Source = new BitmapImage(new Uri("/Resources/invalid.png", UriKind.Relative));
                ImgPortStatus.ToolTip = LocalizationManager.GetString("PortNumberInvalid")
                                       + "\n"
                                       + LocalizationManager.GetString("ChooseAnAppropriatePortNumber");

                return;
            }

            bool isPortValid = App.ViewModel.TrySavePort(inputPort);

            if (!isPortValid)
            {
                // Invalid value : silently resets the default port
                Settings.Default.PortNumber = 7123;
                Settings.Default.Save();

                TxtPort.Text = "7123";

                ImgPortStatus.Source = new BitmapImage(new Uri("/Resources/invalid.png", UriKind.Relative));
                ImgPortStatus.ToolTip = LocalizationManager.GetString("PortNumberInvalid")
                                       + "\n"
                                       + LocalizationManager.GetString("ChooseAnAppropriatePortNumber");

                return;
            }

            // Valid port : green validate icon
            ImgPortStatus.Source = new BitmapImage(new Uri("/Resources/validate.png", UriKind.Relative));
            ImgPortStatus.ToolTip = LocalizationManager.GetString("PortNumberValid");
        }

    }
}
