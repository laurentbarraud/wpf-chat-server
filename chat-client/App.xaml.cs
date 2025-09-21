/// <file>App.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 21th, 2025</date>

using chat_client.Helpers;
using chat_client.Properties;
using System.Configuration;
using System.Data;
using System.Globalization;
using System.Windows;
using System.Windows.Markup;
using System.Runtime.InteropServices;

namespace chat_client
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        /// <summary>
        /// Application startup logic.
        /// Applies saved theme and language preferences before loading the main window.
        /// </summary>
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Attaches a console window for debug output
            AllocConsole();
            Console.WriteLine("[DEBUG] Console attached — ready for runtime logs.");

            // Gets saved theme preference from settings
            bool useDarkTheme = Settings.Default.AppTheme == "Dark";

            // Applies the selected theme with fade animation
            ThemeManager.ApplyTheme(useDarkTheme);

            // Gets saved language preference from settings
            string savedLanguage = Settings.Default.AppLanguage ?? "en";

            // Applies culture globally before any window loads
            var culture = new CultureInfo(savedLanguage);
            Thread.CurrentThread.CurrentUICulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;

            // Initializes localization system
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

