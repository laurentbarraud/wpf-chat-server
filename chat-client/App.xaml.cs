/// <file>App.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 19th, 2025</date>

using chat_client.Helpers;
using chat_client.Properties;
using System.Configuration;
using System.Data;
using System.Globalization;
using System.Windows;
using System.Windows.Markup;

namespace chat_client
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        /// <summary>
        /// Application startup logic.
        /// Applies saved theme and language preferences before loading the main window.
        /// </summary>
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Get saved theme preference from settings
            bool useDarkTheme = Settings.Default.AppTheme == "Dark";

            // Apply the selected theme with fade animation
            ThemeManager.ApplyTheme(useDarkTheme);

            // Get saved language preference from settings
            string savedLanguage = Settings.Default.AppLanguage ?? "en";

            // Apply culture globally before any window loads
            var culture = new CultureInfo(savedLanguage);
            Thread.CurrentThread.CurrentUICulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;

            // Initialize localization system
            LocalizationManager.Initialize(savedLanguage);

            // Launch the main window
            var mainWindow = new MainWindow();
            mainWindow.Show();
        }

        public void TrayIcon_TrayMouseDoubleClick(object sender, RoutedEventArgs e)
        {
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                mainWindow.TrayMenu_Open_Click(sender, e);
            }
        }
    }

}
