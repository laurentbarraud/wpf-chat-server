/// <file>App.xaml.cs</fil
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 27th, 2025</date>

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
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Gathers all args - skip(1) skips exe path
            string[] args = Environment.GetCommandLineArgs().Skip(1).ToArray();

            // Checks for any debug flag
            bool debugMode = args.Any(arg =>
                arg.Equals("--debug", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("--console", StringComparison.OrdinalIgnoreCase) || 
                arg.Equals("-d", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("-c", StringComparison.OrdinalIgnoreCase));

            // Applies all other flags (help, about, theme, encryption…)
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

            // Opens console + enables debug logging
#if DEBUG
            // Debug build: always open console when run under Visual Studio
            ClientLogger.IsDebugEnabled = true;
            ConsoleManager.Show();
            Console.OutputEncoding = System.Text.Encoding.UTF8;
#else
            // Release build: open console only if flag was passed
            if (debugMode)
            {
                ClientLogger.IsDebugEnabled = true;
                ConsoleManager.Show();
                Console.OutputEncoding = System.Text.Encoding.UTF8;
            }
#endif
        }

        public void TrayIcon_TrayMouseDoubleClick(object sender, RoutedEventArgs e)
        {
            if (Application.Current.MainWindow is MainWindow mw)
                mw.TrayMenu_Open_Click(sender, e);
        }
    }
}


