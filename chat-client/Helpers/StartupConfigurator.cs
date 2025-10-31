﻿/// <file>StartupConfigurator.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 31th, 2025</date>

using chat_client.MVVM.ViewModel;
using chat_client.View;
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
                                customPortChosen = portNumberArgument;
                                Properties.Settings.Default.UseCustomPort = true;
                                Properties.Settings.Default.CustomPortNumber = customPortChosen;
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

                // Handle single-dash or slash-normalized flags and bundles
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
                                if (i + 1 < args.Length && int.TryParse(args[i + 1], out var portParameter))
                                {
                                    customPortChosen = portParameter;
                                    Properties.Settings.Default.UseCustomPort = true;
                                    Properties.Settings.Default.CustomPortNumber = customPortChosen;
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
                                    usernameChosen = flagArgument;
                                else if (flag == 'p' && int.TryParse(flagArgument, out var customPortValue))
                                {
                                    customPortChosen = customPortValue;
                                    Properties.Settings.Default.UseCustomPort = true;
                                    Properties.Settings.Default.CustomPortNumber = customPortChosen;
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

            // Applies language choice globally
            if (!string.IsNullOrEmpty(languageChosen))
            {
                LocalizationManager.Initialize(languageChosen);
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

            // Re-apply chosen localization
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
                    LocalizationManager.Initialize("en");
                    Properties.Settings.Default.AppLanguage = "en";
                }
            }

            // Retrieve window and view model
            if (Application.Current.MainWindow is MainWindow mainWindow &&
                mainWindow.ViewModel is MainViewModel viewModel)
            {
                if (enableEncryption)
                {
                    Properties.Settings.Default.UseEncryption = true;
                    viewModel.InitializeEncryption();
                }

                if (!string.IsNullOrEmpty(themeChosen))
                {
                    bool isDarkThemeChosen = themeChosen.Equals("dark", System.StringComparison.OrdinalIgnoreCase);
                    ThemeManager.ApplyTheme(isDarkThemeChosen);
                    Properties.Settings.Default.AppTheme = isDarkThemeChosen ? "Dark" : "Light";
                }

                if (reduceInTray)
                    Properties.Settings.Default.ReduceToTray = true;

                // Show debug console if requested
                if (debugMode)
                {
                    ClientLogger.IsDebugEnabled = true;
                    ConsoleManager.Show();
                }

                if (!string.IsNullOrEmpty(usernameChosen))
                {
                    viewModel.Username = usernameChosen;
                    mainWindow.Loaded += (_, _) =>
                    {
                        if (viewModel.ConnectDisconnectCommand?.CanExecute(null) == true)
                            viewModel.ConnectDisconnectCommand.Execute(null);
                    };
                }

                Properties.Settings.Default.Save();
            }
        }
    }
}



