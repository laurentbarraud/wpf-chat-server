/// <file>App.xaml.cs</fil
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 12th, 2025</date>

using chat_client.Helpers;
using chat_client.Properties;
using System;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Windows;

namespace chat_client
{
    public partial class App : Application
    {
        /// <summary>
        /// Overrides startup to apply command-line flags, set up culture,
        /// show the main window, and only then open the debug console if requested.
        /// </summary>
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Gathers all user-supplied args - Skip(1) to skip the .exe path
            string[] args = Environment
                .GetCommandLineArgs()
                .Skip(1)
                .ToArray();

            // Detects "--debug" or "--console" upfront
            bool debugMode = args.Any(arg =>
                arg.Equals("--debug", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("--console", StringComparison.OrdinalIgnoreCase));

            // Let StartupConfigurator handle everything else
            StartupConfigurator.ApplyStartupArguments(args);

            // Culture & localization
            string language = Settings.Default.AppLanguage ?? "en";
            var culture = new CultureInfo(language);
            Thread.CurrentThread.CurrentCulture = culture;
            Thread.CurrentThread.CurrentUICulture = culture;
            CultureInfo.DefaultThreadCurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;
            LocalizationManager.Initialize(language);

            // Creates and shows the main window
            var mainWindow = new MainWindow();
            Application.Current.MainWindow = mainWindow;
            mainWindow.Show();

            // Enables debug logging and opens console if requested
            if (debugMode)
            {
                ClientLogger.IsDebugEnabled = true;
                ConsoleManager.Show();
            }
        }

        public void TrayIcon_TrayMouseDoubleClick(object sender, RoutedEventArgs e)
        {
            if (Application.Current.MainWindow is MainWindow mw)
                mw.TrayMenu_Open_Click(sender, e);
        }
    }
}


