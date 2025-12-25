/// <file>StartupConfigurator.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 26th, 2025</date>

using chat_client.MVVM.ViewModel;
using chat_client.View;
using System;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Documents;
using System.Xml.Linq;

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
            string themeChosen = "light";
            string langCodeChosen = "en";
            int customPortChosen;
            bool enableEncryption = false;
            bool reduceInTray = false;
            bool debugMode = false;
            bool showHelp = false;
            bool showAbout = false;

            /// <summary> Iterates through each argument with support for bundled short flags like -teu </summary>
            for (int i = 0; i < args.Length; i++)
            {
                string rawArg = args[i];
                if (string.IsNullOrEmpty(rawArg))
                    continue;

                /// <summary> Normalize: accepts both Unix-style (--) and Windows-style (/) </summary>
                string arg = rawArg.StartsWith("/") ? "-" + rawArg.Substring(1) : rawArg;
                arg = arg.ToLowerInvariant();

                // Long options (start with --)
                if (arg.StartsWith("--"))
                {
                    switch (arg)
                    {
                        case "--username":
                            if (i + 1 < args.Length)
                                usernameChosen = args[++i];
                            break;
                        case "--port":
                            if (i + 1 < args.Length && int.TryParse(args[i + 1], out var portNumberArgument))
                            {
                                Properties.Settings.Default.PortNumber = portNumberArgument;
                                i++;
                            }
                            break;
                        case "--dark":
                            themeChosen = "dark";
                            break;
                        case "--light":
                            themeChosen = "light";
                            break;
                        case "--en":
                        case "--english":
                            langCodeChosen = "en";
                            break;
                        case "--fr":
                        case "--french":
                            langCodeChosen = "fr";
                            break;                      
                        case "--encrypted":
                            enableEncryption = true;
                            break;
                        case "--reduce":
                        case "--tray":
                        case "--minimize":
                            reduceInTray = true;
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
                            break;
                    }
                    continue;
                }

                /// <summary> Handles single-dash or slash-normalized flags and bundles </summary>
                if (arg.StartsWith("-") && arg.Length >= 2)
                {
                    if (arg == "-?")
                    {
                        showHelp = true;
                        continue;
                    }
                    if (arg.Length == 2)
                    {
                        char flag = arg[1];
                        switch (flag)
                        {
                            case 'u':
                                if (i + 1 < args.Length)
                                    usernameChosen = args[++i];
                                break;
                            case 'p':
                                if (i + 1 < args.Length && int.TryParse(args[i + 1], out var inputPort))
                                {
                                    customPortChosen = inputPort;
                                    Properties.Settings.Default.PortNumber = customPortChosen;
                                    i++;
                                }
                                break;
                            case 'e':
                                enableEncryption = true;
                                break;
                            case 'r':
                            case 'm':
                            case 't':
                                reduceInTray = true;
                                break;
                            case 'h':
                            case '?':
                                showHelp = true;
                                break;
                            case 'v':
                                showAbout = true;
                                break;
                            default:
                                break;
                        }
                        continue;
                    }

                    for (int j = 1; j < arg.Length; j++)
                    {
                        char flag = arg[j];

                        if (flag == 'u' || flag == 'p')
                        {
                            string flagArgument = "";
                            if (j + 1 < arg.Length)
                            {
                                flagArgument = arg.Substring(j + 1);
                                j = arg.Length;
                            }
                            else if (i + 1 < args.Length)
                            {
                                flagArgument = args[++i];
                            }

                            if (!string.IsNullOrEmpty(flagArgument))
                            {
                                if (flag == 'u')
                                {
                                    usernameChosen = flagArgument;
                                }
                                else if (flag == 'p')
                                {
                                    /// <summary> Tries to parse the port number </summary>
                                    if (int.TryParse(flagArgument, out var inputPort))
                                    {
                                        /// <summary> Validates the port using the same logic as the UI </summary>
                                        bool isPortValid = MainViewModel.TrySavePort(inputPort);

                                        ///<summary> Only saves if valid — otherwise does nothing </summary>
                                        if (isPortValid)
                                        {
                                            Properties.Settings.Default.PortNumber = inputPort;
                                            Properties.Settings.Default.Save();
                                        }
                                    }

                                    // If parsing fails → do nothing (keep existing port)
                                }
                            }
                            break;
                        }

                        switch (flag)
                        {
                            case 'e':
                                enableEncryption = true;
                                break;
                            case 'r':
                            case 'm':
                            case 't':
                                reduceInTray = true;
                                break;
                            case 'h':
                            case '?':
                                showHelp = true;
                                break;
                            case 'v':
                                showAbout = true;
                                break;
                            default:
                                break;
                        }
                    }
                    continue;
                }
            }

            ///<summary> Applies chosen localization </summary>
            if (!string.IsNullOrEmpty(langCodeChosen))
            {
                var supported = new[] { "en", "fr" };
                if (supported.Contains(langCodeChosen.ToLowerInvariant()))
                {
                    LocalizationManager.InitializeLocalization(langCodeChosen);
                    Properties.Settings.Default.AppLanguageCode = langCodeChosen;
                }
                else
                {
                    LocalizationManager.InitializeLocalization("en");
                    Properties.Settings.Default.AppLanguageCode = "en";
                }
            }

            // Shows help and exits
            if (showHelp)
            {
                var about = new AboutWindow();
                about.ShowCommandLineArgumentsHelp();
                return;
            }

            // Shows About dialog and exits
            if (showAbout)
            {
                var aboutWindow = new AboutWindow();
                aboutWindow.ShowDialog();
                Environment.Exit(0);
                return;
            }

            // Retrieves window and view model if available
            if (Application.Current.MainWindow is MainWindow mainWindow &&
                mainWindow.viewModel is MainViewModel viewModel)
            {
                // Persists the preference first
                Properties.Settings.Default.UseEncryption = enableEncryption;
                Properties.Settings.Default.Save();

                // Updates the source on the view model;
                // the ViewModel decides when/how to start or stop the pipeline.
                viewModel.UseEncryption = enableEncryption;

                // If a username was chosen
                if (!string.IsNullOrEmpty(usernameChosen))
                {
                    // Sets the chosen username on the VM
                    viewModel.Username = usernameChosen;

                    // We assign the name onLoaded before the lambda to be able to use it inside the same lambda.
                    RoutedEventHandler onLoaded = null!;
                    onLoaded = (s, e) =>
                    {
                        // Unsubscribes immediately to avoid being called back several times
                        mainWindow.Loaded -= onLoaded;

                        // If the command is available and executable
                        if (viewModel.ConnectDisconnectCommand?.CanExecute(null) == true)
                        {
                            // Executes the command
                            viewModel.ConnectDisconnectCommand.Execute(null);
                        }
                    };

                    // If the window is already loaded
                    if (mainWindow.IsLoaded)
                    {
                        // Direct invocation uses the same logic as the handler
                        if (viewModel.ConnectDisconnectCommand?.CanExecute(null) == true)
                        {
                            viewModel.ConnectDisconnectCommand.Execute(null);
                        }
                    }

                    else
                    {
                        // Attaches the handler
                        mainWindow.Loaded += onLoaded;
                    }
                }
            }
            else
            {
                ClientLogger.Log("MainWindow or MainViewModel not found during startup configuration.", ClientLogLevel.Warn);
            }

            // Theme selection
            if (!string.IsNullOrEmpty(themeChosen))
            {
                bool isDarkThemeChosen = themeChosen.Equals("dark", StringComparison.OrdinalIgnoreCase);
                ThemeManager.ApplyTheme(isDarkThemeChosen);
                Properties.Settings.Default.AppTheme = isDarkThemeChosen ? "dark" : "light";
            }

            // Reduce app to tray setting
            if (reduceInTray)
            {
                Properties.Settings.Default.ReduceToTray = true;
            }

            // Shows debug console
            if (debugMode)
            {
                ClientLogger.IsDebugEnabled = true;
                ConsoleManager.Show();
            }

            // Persists settings last
            Properties.Settings.Default.Save();
        }
    }
}



