/// <file>StartupConfigurator.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 8th, 2025</date>

using chat_client.MVVM.ViewModel;
using chat_client.View;
using System;
using System.Linq;
using System.Windows;

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
            int customPortChosen;
            bool enableEncryption = false;
            bool reduceInTray = false;
            bool debugMode = false;
            bool showHelp = false;
            bool showAbout = false;

            // Iterates through each argument with support for bundled short flags like -teu
            for (int i = 0; i < args.Length; i++)
            {
                string rawArg = args[i];
                if (string.IsNullOrEmpty(rawArg))
                    continue;

                // Normalize: accepts both Unix-style (--) and Windows-style (/)
                // Treats leading '/' as equivalent to single '-' for parsing purposes.
                string arg = rawArg.StartsWith("/") ? "-" + rawArg.Substring(1) : rawArg;
                // Lowercases the input for case-insensitive comparison
                arg = arg.ToLowerInvariant();

                // Long options (start with --) are handled here
                if (arg.StartsWith("--"))
                {
                    switch (arg)
                    {
                        // Username long form
                        case "--username":
                            if (i + 1 < args.Length)
                                usernameChosen = args[++i];
                            break;

                        case "--port":
                            if (i + 1 < args.Length && int.TryParse(args[i + 1], out var portNumberArgument))
                            {
                                customPortChosen = portNumberArgument;
                                Properties.Settings.Default.UseCustomPort = true;
                                Properties.Settings.Default.CustomPortNumber = customPortChosen;
                                i++;
                            }
                            break;

                        case "--theme":
                        case "/theme": 
                            if (i + 1 < args.Length)
                                themeChosen = args[++i];
                            break;

                        case "--dark":
                            themeChosen = "dark";
                            break;

                        case "--light":
                            themeChosen = "light";
                            break;

                        case "--en":
                        case "--english":
                            languageChosen = "en";
                            break;

                        case "--fr":
                        case "--french":
                            languageChosen = "fr";
                            break;

                        case "--lang":
                        case "--language":
                            if (i + 1 < args.Length)
                            {
                                var raw = args[++i].ToLowerInvariant();
                                if (raw == "french" || raw == "français" || raw == "francais" || raw == "fr")
                                    languageChosen = "fr";
                                else if (raw == "english" || raw == "anglais" || raw == "en")
                                    languageChosen = "en";
                                else
                                    languageChosen = "en";
                            }
                            break;

                        case "--encrypted":
                            enableEncryption = true;
                            break;

                        case "--reduce":
                        case "--tray":
                        case "--minimize":
                            reduceInTray = true;
                            break;

                        case "--console":
                        case "--debug":
                            debugMode = true;
                            break;

                        case "--help":
                            showHelp = true;
                            break;

                        case "--about":
                        case "--author":
                        case "--credits":
                        case "--licence":
                        case "--license":
                        case "--version":
                            showAbout = true;
                            break;

                        default:
                            // Unknown long flag - ignore or log if desired
                            break;
                    }

                    continue;
                }

                // Handle single-dash or slash-normalized flags.
                // Support bundled short flags like -teu
                if (arg.StartsWith("-") && arg.Length >= 2)
                {
                    // If arg is exactly "-?" treat as help
                    if (arg == "-?")
                    {
                        showHelp = true;
                        continue;
                    }

                    // If arg is exactly "-v" or "-h" etc. (single-char), treat directly
                    if (arg.Length == 2)
                    {
                        char flag = arg[1];
                        switch (flag)
                        {
                            // Username short (-u) expects a parameter
                            case 'u':
                                if (i + 1 < args.Length)
                                    usernameChosen = args[++i];
                                break;

                            // Port short (-p) expects a parameter
                            case 'p':
                                if (i + 1 < args.Length && int.TryParse(args[i + 1], out var portParameter))
                                {
                                    customPortChosen = portParameter;
                                    Properties.Settings.Default.UseCustomPort = true;
                                    Properties.Settings.Default.CustomPortNumber = customPortChosen;
                                    i++;
                                }
                                break;

                            // Theme dark/light short single-letter mapping
                            case 'd':
                                themeChosen = "dark";
                                break;
                            case 'l':
                                themeChosen = "light";
                                break;

                            // Language direct short not used to avoid conflict with -l theme short
                            // Provide long variants --en/--fr instead

                            // Encryption
                            case 'e':
                                enableEncryption = true;
                                break;

                            // Reduce to tray short
                            case 'r':
                            case 'm':
                            case 't': // note: you intentionally use -t as reduceInTray in your current mapping
                                reduceInTray = true;
                                break;

                            // Console / debug shorthand
                            case 'c':
                                debugMode = true;
                                break;

                            // Help / About / Version
                            case 'h':
                                showHelp = true;
                                break;
                            case 'v':
                                showAbout = true;
                                break;
                            case '?':
                                showHelp = true;
                                break;

                            default:
                                // Unknown short flag - ignore
                                break;
                        }

                        continue;
                    }

                    // Bundled short flags: -xyz
                    // We iterate each character after the first '-' and handle it.
                    // If a flag requires a parameter (u or p), it consumes the remainder of the token as value
                    // or, if it is the last char, consumes the next args[] element.
                    for (int j = 1; j < arg.Length; j++)
                    {
                        char flag = arg[j];

                        // Flags that require an argument
                        if (flag == 'u' || flag == 'p')
                        {
                            string flagArgument = "";

                            // If there are characters remaining in the same token after this flag,
                            // treats them as the parameter
                            if (j + 1 < arg.Length)
                            {
                                flagArgument = arg.Substring(j + 1);
                                // moves j to end to stop processing remaining chars
                                j = arg.Length;
                            }
                            else
                            {
                                // else takes the next argv element as the parameter
                                if (i + 1 < args.Length)
                                    flagArgument = args[++i];
                            }

                            if (!string.IsNullOrEmpty(flagArgument))
                            {
                                if (flag == 'u') usernameChosen = flagArgument;
                                else if (flag == 'p' && int.TryParse(flagArgument, out var customPortValue))
                                {
                                    customPortChosen = customPortValue;
                                    Properties.Settings.Default.UseCustomPort = true;
                                    Properties.Settings.Default.CustomPortNumber = customPortChosen;
                                }
                            }

                            // parameter consumed, continue outer loop
                            break;
                        }

                        // Flags without parameters
                        switch (flag)
                        {
                            case 'd':
                                themeChosen = "dark";
                                break;
                            case 'l':
                                themeChosen = "light";
                                break;
                            case 'e':
                                enableEncryption = true;
                                break;
                            case 'r':
                            case 'm':
                            case 't':
                                reduceInTray = true;
                                break;
                            case 'c':
                                debugMode = true;
                                break;
                            case 'h':
                            case '?':
                                showHelp = true;
                                break;
                            case 'v':
                                showAbout = true;
                                break;
                            default:
                                // Unknown short flag - gets ignored
                                break;
                        }
                    } 

                    continue;           // when we have scanned a token like -x and applied the necessary actions,
                                        // we executes continue to move on to the next token and not fall back
                                        // into the logic that follows.
                }
            }

            // Applies language choice globally
            if (!string.IsNullOrEmpty(languageChosen))
            {
                LocalizationManager.Initialize(languageChosen);
            }

            // Shows arguments summary in a message box and exits early
            if (showHelp)
            {
                var about = new AboutWindow();
                about.ShowCommandLineArgumentsHelp();
                return;
            }

            // Shows About dialog and exits early
            if (showAbout)
            {
                var aboutWindow = new AboutWindow();
                aboutWindow.ShowDialog();   
                Application.Current.Shutdown();
                return;
            }

            // Initializes localization if a language flag was provided
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
                    // Fallbacks to English if unsupported
                    LocalizationManager.Initialize("en");
                    Properties.Settings.Default.AppLanguage = "en";
                }
            }       

            // Retrieves main window and its view model for further actions
            if (Application.Current.MainWindow is MainWindow mainWindow && mainWindow.ViewModel is MainViewModel viewModel)
            {
                // Enables encryption on startup if requested
                if (enableEncryption)
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

                // Auto-connects if a username was provided
                if (!string.IsNullOrEmpty(usernameChosen))
                {
                    viewModel.Username = usernameChosen;

                    mainWindow.Loaded += (_, _) =>
                    {
                        if (viewModel.ConnectDisconnectCommand?.CanExecute(null) == true)
                            viewModel.ConnectDisconnectCommand.Execute(null);
                    };
                }

                // Persists all updated settings
                Properties.Settings.Default.Save();
            }

        }
    }
}


