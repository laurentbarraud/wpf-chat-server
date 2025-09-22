/// <file>App.xaml.cs</fil
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 22th, 2025</date>

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
        /// Handles application startup sequence.
        /// Creates the main window, applies command-line arguments if present,
        /// and falls back to saved preferences otherwise.
        /// Ensures global culture is set before rendering UI.
        /// </summary>
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Creates and registers the main window before applying arguments
            var mainWindow = new MainWindow();
            Application.Current.MainWindow = mainWindow;

            // Extracts command-line arguments (excluding executable path)
            string[] args = Environment.GetCommandLineArgs().Skip(1).ToArray();

            if (args.Length > 0)
            {
                // Applies all startup arguments (theme, language, encryption, etc.)
                StartupConfigurator.ApplyStartupArguments(args);

                // Applies remaining preferences not overridden by arguments
                string fallbackLanguage = Settings.Default.AppLanguage ?? "en";
                LocalizationManager.Initialize(fallbackLanguage);

                bool fallbackTheme = Settings.Default.AppTheme?.ToLower() == "dark";
                ThemeManager.ApplyTheme(fallbackTheme);
            }
            else
            {
                // No arguments provided — applies saved preferences only
                string savedLanguage = Settings.Default.AppLanguage ?? "en";
                LocalizationManager.Initialize(savedLanguage);

                string savedTheme = Settings.Default.AppTheme?.ToLower() ?? "light";
                mainWindow.ThemeToggle.IsChecked = savedTheme == "dark";
            }

            // Applies global culture before any UI is rendered
            var culture = new System.Globalization.CultureInfo(Settings.Default.AppLanguage ?? "en");
            System.Threading.Thread.CurrentThread.CurrentUICulture = culture;
            System.Globalization.CultureInfo.DefaultThreadCurrentUICulture = culture;

            // Displays the main window
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

