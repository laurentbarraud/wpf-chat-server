/// <file>StartupConfigurator.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 30th, 2025</date>
using System;
using System.Linq;
using System.Windows;
using chat_client.View;

namespace chat_client.Helpers
{
    /// <summary>
    /// Parses and applies command-line startup arguments to configure the chat client.
    /// Supports aliases for username, port, theme, language (including --en/--fr),
    /// encryption, tray behavior, debug console, help, and About window.
    /// Displays help in a message box, opens About dialog, initializes localization, 
    /// applies settings, and triggers auto-connect if username is provided.
    /// </summary>
    public static class StartupConfigurator
    {
        /// <summary>
        /// Reads the args array and configures the application accordingly:
        ///   • Parses username, port, theme, language, encryption, tray, debug, help, and about flags.
        ///   • Shows a message box with help text if help is requested, then exits.
        ///   • Opens the About window if requested, then exits.
        ///   • Initializes localization based on language flags (--language, --en, --fr).
        ///   • Applies encryption, theme, tray, debug console, and username/auto-connect.
        ///   • Saves all updated settings at the end.
        /// </summary>
        /// <param name="args">Array of command-line arguments.</param>
        public static void ApplyStartupArguments(string[] args)
        {
            if (args == null || args.Length == 0)
                return;

            // Variables to hold parsed values
            string usernameChosen = "";
            string themeChosen = "";
            string languageChosen = "";
            int port;
            bool enableEncryption = false;
            bool reduceInTray = false;
            bool debugMode = false;
            bool showHelp = false;
            bool showAbout = false;

            // Iterate through each argument
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i].ToLowerInvariant();
                switch (arg)
                {
                    // Username flags
                    case "--username":
                    case "-u":
                    case "/username":
                    case "/u":
                    case "-user":
                    case "/user":
                        if (i + 1 < args.Length)
                            usernameChosen = args[++i];
                        break;

                    // Custom port flags
                    case "--port":
                    case "-p":
                    case "/port":
                    case "/p":
                        if (i + 1 < args.Length && int.TryParse(args[i + 1], out var p))
                        {
                            port = p;
                            Properties.Settings.Default.UseCustomPort = true;
                            Properties.Settings.Default.CustomPortNumber = port;
                            i++;
                        }
                        break;

                    // Theme flags
                    case "--theme":
                    case "-t":
                    case "/theme":
                    case "/t":
                        if (i + 1 < args.Length)
                            themeChosen = args[++i];
                        break;
                    case "--dark":
                    case "/dark":
                        themeChosen = "dark";
                        break;
                    case "--light":
                    case "/light":
                        themeChosen = "light";
                        break;

                    // Explicit language flags and normalization
                    case "--language":
                    case "-l":
                    case "/language":
                    case "/l":
                    case "--lang":
                    case "/lang":
                        if (i + 1 < args.Length)
                        {
                            // Reads the raw language token and normalize it
                            var langArgument = args[++i].ToLowerInvariant();

                            // Map any French variant to "fr"
                            if (langArgument == "french"
                             || langArgument == "français"
                             || langArgument == "francais"
                             || langArgument == "fr")
                            {
                                languageChosen = "fr";
                            }
                            // Map any English variant to "en"
                            else if (langArgument == "english"
                                  || langArgument == "anglais"
                                  || langArgument == "en")
                            {
                                languageChosen = "en";
                            }
                            else
                            {
                                // Falls back on English if the language code is not recognized
                                languageChosen = "en";
                            }
                        }
                        break;


                    // Encryption flag
                    case "--encrypted":
                    case "-e":
                    case "/encrypted":
                    case "/e":
                        enableEncryption = true;
                        break;

                    // Reduce to tray flags
                    case "--reduceintray":
                    case "-r":
                    case "/reduceintray":
                    case "/r":
                    case "--reduce":
                    case "/reduce":
                        reduceInTray = true;
                        break;

                    // Debug console flag
                    case "--debug":
                    case "-d":
                    case "/debug":
                    case "/d":
                        debugMode = true;
                        break;

                    // Help flags
                    case "--help":
                    case "-h":
                    case "-?":
                    case "/help":
                    case "/h":
                    case "/?":
                        showHelp = true;
                        break;

                    // About flags
                    case "--about":
                    case "/about":
                        showAbout = true;
                        break;
                }
            }

            // Shows help in a message box and exit early
            if (showHelp)
            {
                var helpLines = new[]
                {
                    LocalizationManager.GetString("CliOptionsHelpLine1"),
                    LocalizationManager.GetString("CliOptionsHelpLine2"),
                    LocalizationManager.GetString("CliOptionsHelpLine3"),
                    LocalizationManager.GetString("CliOptionsHelpLine4"),
                    LocalizationManager.GetString("CliOptionsHelpLine5"),
                    LocalizationManager.GetString("CliOptionsHelpLine6"),
                    LocalizationManager.GetString("CliOptionsHelpLine7"),
                    LocalizationManager.GetString("CliOptionsHelpLine8"),
                    LocalizationManager.GetString("CliOptionsHelpLine9"),
                    LocalizationManager.GetString("CliOptionsHelpLine10")
                };
                string helpText = string.Join(Environment.NewLine, helpLines);

                // Displays a stylized message box containing usage instructions
                MessageBox.Show(
                    helpText,
                    LocalizationManager.GetString("CliOptionsHelpTitle"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                Application.Current.Shutdown();
                return;
            }

            // Shows About dialog and exit early
            if (showAbout)
            {
                var aboutWindow = new AboutWindow();
                aboutWindow.ShowDialog();   // Blocks until user clicks OK
                Application.Current.Shutdown();
                return;
            }

            // Initialize localization if a language flag was provided
            if (!string.IsNullOrEmpty(languageChosen))
            {
                var supported = new[] { "en", "fr" };
                if (supported.Contains(languageChosen.ToLowerInvariant()))
                {
                    LocalizationManager.Initialize(languageChosen);
                    Properties.Settings.Default.AppLanguage = languageChosen;
                }
                else
                {
                    // Fallback to English if unsupported
                    LocalizationManager.Initialize("en");
                    Properties.Settings.Default.AppLanguage = "en";
                }
            }

            // Applies custom port if set
            // (Properties.Settings.Default.CustomPortNumber was set during parsing)

            // Retrieves main window and its view model for further actions
            var mainWindow = Application.Current.MainWindow as MainWindow;
            var viewModel = mainWindow?.ViewModel;

            // Enables encryption on startup if requested
            if (enableEncryption && viewModel != null)
            {
                Properties.Settings.Default.UseEncryption = true;
                viewModel.InitializeEncryption();
            }

            // Applies theme if specified
            if (!string.IsNullOrEmpty(themeChosen))
            {
                bool isDarkThemeChosen = themeChosen.Equals("dark", StringComparison.OrdinalIgnoreCase);
                ThemeManager.ApplyTheme(isDarkThemeChosen);
                Properties.Settings.Default.AppTheme = isDarkThemeChosen ? "Dark" : "Light";
            }

            // Enables minimize-to-tray if requested
            if (reduceInTray)
                Properties.Settings.Default.ReduceToTray = true;

            // Shows debug console if requested
            if (debugMode)
                ConsoleManager.Show();

            // Auto-connects if username was provided
            if (!string.IsNullOrEmpty(usernameChosen) && mainWindow != null)
            {
                mainWindow.TxtUsername.Text = usernameChosen;
                mainWindow.CmdConnectDisconnect_Click(null, new RoutedEventArgs());
            }

            // Persists all updated settings
            Properties.Settings.Default.Save();
        }
    }
}


