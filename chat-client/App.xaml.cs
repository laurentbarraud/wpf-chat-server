/// <file>App.xaml.cs</fil
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 28th, 2025</date>

using chat_client.Helpers;
using chat_client.Properties;
using System.Globalization;
using System.Windows;

namespace chat_client
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Extracts command-line arguments (excluding executable path)
            string[] args = Environment.GetCommandLineArgs().Skip(1).ToArray();

            // Determines language from arguments or saved settings
            string language = Settings.Default.AppLanguage ?? "en";

            // Applies global culture before any UI is created
            var culture = new CultureInfo(language);
            Thread.CurrentThread.CurrentUICulture = culture;
            Thread.CurrentThread.CurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;
            CultureInfo.DefaultThreadCurrentCulture = culture;

            // Initializes localization manager with selected language
            LocalizationManager.Initialize(language);

            // Sets log verbosity based on build configuration or command-line flag
            #if DEBUG
                ClientLogger.IsDebugEnabled = true;
            #else
                ClientLogger.IsDebugEnabled = args.Contains("--debug");
            #endif

            // Creates and registers the main window
            var mainWindow = new MainWindow();
            Application.Current.MainWindow = mainWindow;

            if (args.Length > 0)
            {
                // Applies startup arguments (theme, encryption, etc.)
                StartupConfigurator.ApplyStartupArguments(args);

                // Applies fallback theme if not overridden
                bool fallbackTheme = Settings.Default.AppTheme?.ToLower() == "dark";
                ThemeManager.ApplyTheme(fallbackTheme);
            }
            else
            {
                // Applies saved preferences only
                string savedTheme = Settings.Default.AppTheme?.ToLower() ?? "light";
                mainWindow.ThemeToggle.IsChecked = savedTheme == "dark";
            }

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

