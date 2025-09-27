/// <file>StartupConfigurator.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 27th, 2025</date>

using chat_client.View;
using ChatClient.Helpers;
using System;
using System.Globalization;
using System.Linq;
using System.Windows;

namespace chat_client.Helpers
{
    /// <summary>
    /// Parses and applies command-line startup arguments to configure the chat client.
    /// Supports flexible aliases for username, encryption, theme, language, port, tray behavior, debug console, and About window.
    /// Applies settings, initializes localization, and triggers auto-connect if username is provided.
    /// Opens the About window and exits if --about is passed.
    /// </summary>
    public static class StartupConfigurator
    {
        public static void ApplyStartupArguments(string[] args)
        {
            if (args == null || args.Length == 0)
                return;

            // Declares variables to store parsed arguments
            string username = "";
            string theme = "";
            string language = "";
            int port = 7123;
            bool enableEncryption = false;
            bool reduceInTray = false;
            bool debugMode = false;
            bool showHelp = false;
            bool showAbout = false;

            // Parses each argument and maps it to its corresponding behavior
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i].ToLower();

                switch (arg)
                {
                    case "--username":
                    case "-u":
                    case "/username":
                    case "/u":
                    case "-user":
                    case "/user":
                        if (i + 1 < args.Length)
                            username = args[++i];
                        break;

                    case "--port":
                    case "-p":
                    case "/port":
                    case "/p":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out int parsedPort))
                        {
                            port = parsedPort;
                            Properties.Settings.Default.UseCustomPort = true;
                            Properties.Settings.Default.CustomPortNumber = port;
                            i++;
                        }
                        break;

                    case "--theme":
                    case "-t":
                    case "/theme":
                    case "/t":
                        if (i + 1 < args.Length)
                            theme = args[++i];
                        break;

                    case "--dark":
                    case "/dark":
                        theme = "dark";
                        break;

                    case "--light":
                    case "/light":
                        theme = "light";
                        break;

                    case "--language":
                    case "-l":
                    case "/language":
                    case "/l":
                    case "--lang":
                    case "/lang":
                        if (i + 1 < args.Length)
                            language = args[++i];
                        break;

                    case "--encrypted":
                    case "-e":
                    case "/encrypted":
                    case "/e":
                        enableEncryption = true;
                        break;

                    case "--reduceintray":
                    case "-r":
                    case "/reduceintray":
                    case "/r":
                    case "--reduce":
                    case "/reduce":
                        reduceInTray = true;
                        break;

                    case "--debug":
                    case "-d":
                    case "/debug":
                    case "/d":
                        debugMode = true;
                        break;

                    case "--help":
                    case "-h":
                    case "-?":
                    case "/help":
                    case "/h":
                    case "/?":
                        showHelp = true;
                        break;

                    case "--about":
                    case "/about":
                        showAbout = true;
                        break;
                }
            }

            // Displays help message and exits if --help is passed
            if (showHelp)
            {
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine1"), ClientLogLevel.Info);
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine2"), ClientLogLevel.Info);
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine3"), ClientLogLevel.Info);
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine4"), ClientLogLevel.Info);
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine5"), ClientLogLevel.Info);
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine6"), ClientLogLevel.Info);
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine7"), ClientLogLevel.Info);
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine8"), ClientLogLevel.Info);
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine9"), ClientLogLevel.Info);
                ClientLogger.Log(LocalizationManager.GetString("CliOptionsHelpLine10"), ClientLogLevel.Info);
                return;
            }

            // Opens AboutWindow and exits if --about is passed
            if (showAbout)
            {
                var aboutWindow = new AboutWindow();
                aboutWindow.ShowDialog(); // Blocks until user clicks OK
                Application.Current.Shutdown(); // Closes app after AboutWindow
                return;
            }

            // Initializes localization before any UI is shown
            if (!string.IsNullOrEmpty(language))
            {
                var supportedLanguages = new[] { "en", "fr" };
                if (supportedLanguages.Contains(language.ToLower()))
                {
                    LocalizationManager.Initialize(language);
                    Properties.Settings.Default.AppLanguage = language;
                    ClientLogger.Log($"[Startup] Language set: {language}", ClientLogLevel.Info);
                }
                else
                {
                    ClientLogger.Log($"[Startup] Unsupported language: {language}. Defaulting to 'en'.", ClientLogLevel.Info);
                    LocalizationManager.Initialize("en");
                    Properties.Settings.Default.AppLanguage = "en";
                }
            }

            // Retrieves main window and its view model
            var mainWindow = Application.Current.MainWindow as MainWindow;
            var viewModel = mainWindow?.ViewModel;

            // Enables encryption if requested
            if (enableEncryption && viewModel != null)
            {
                Properties.Settings.Default.UseEncryption = true;

                // Attempts to initialize encryption; logs outcome based on the return value
                if (viewModel.InitializeEncryption())
                    ClientLogger.Log("[Startup] Encryption enabled.", ClientLogLevel.Info);
                else
                    ClientLogger.Log("[Startup] Encryption initialization failed.", ClientLogLevel.Error);
            }


            // Applies theme if specified
            if (!string.IsNullOrEmpty(theme))
            {
                bool isDark = theme.ToLower() == "dark";
                ThemeManager.ApplyTheme(isDark);
                Properties.Settings.Default.AppTheme = isDark ? "Dark" : "Light";
                ClientLogger.Log($"[Startup] Theme applied: {(isDark ? "dark" : "light")}", ClientLogLevel.Info);
            }

            // Enables tray minimization if requested
            if (reduceInTray)
            {
                Properties.Settings.Default.ReduceToTray = true;
                ClientLogger.Log("[Startup] Reduce to tray enabled.", ClientLogLevel.Info);
            }

            // Shows debug console if requested
            if (debugMode)
            {
                ConsoleManager.Show();
                ClientLogger.Log("[Startup] Debug console shown.", ClientLogLevel.Info);
            }

            // Applies username and triggers auto-connect
            if (!string.IsNullOrEmpty(username) && mainWindow != null)
            {
                mainWindow.TxtUsername.Text = username;
                ClientLogger.Log($"[Startup] Username set: {username}", ClientLogLevel.Info);

                mainWindow.CmdConnectDisconnect_Click(new object(), new RoutedEventArgs());
            }

            // Saves all updated settings
            Properties.Settings.Default.Save();
        }
    }
}

