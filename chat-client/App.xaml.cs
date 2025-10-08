/// <file>App.xaml.cs</fil
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 8th, 2025</date>

using chat_client.Helpers;
using chat_client.Properties;
using System.Globalization;
using System.Windows;

namespace chat_client
{
    public partial class App : Application
    {
        /// <summary>
        /// Overrides startup to optionally show a console in DEBUG,
        /// set up culture, apply any release-time flags,
        /// and finally create and show the main window.
        /// </summary>
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Collects command-line arguments (exe path excluded)
            string[] args = Environment.GetCommandLineArgs().Skip(1).ToArray();

            // In DEBUG builds, enable debug logging and show console
            #if DEBUG
            ClientLogger.IsDebugEnabled = true;
            ConsoleManager.Show();
            #endif

            // Culture & localization
            string language = Settings.Default.AppLanguage ?? "en";
            var culture = new CultureInfo(language);
            Thread.CurrentThread.CurrentCulture = culture;
            Thread.CurrentThread.CurrentUICulture = culture;
            CultureInfo.DefaultThreadCurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;
            LocalizationManager.Initialize(language);

            // Applies command line arguments
            if (args.Length > 0)
            {
                StartupConfigurator.ApplyStartupArguments(args);
            }

            // Instantiates and shows the main window
            var mainWindow = new MainWindow();
            Application.Current.MainWindow = mainWindow;
            mainWindow.Show();
        }

        public void TrayIcon_TrayMouseDoubleClick(object sender, RoutedEventArgs e)
        {
            if (Application.Current.MainWindow is MainWindow mw)
                mw.TrayMenu_Open_Click(sender, e);
        }
    }
}


