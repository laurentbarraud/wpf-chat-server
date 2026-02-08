/// <file>StartupConfigurator.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 8th, 2026</date>

using ChatClient.MVVM.View;
using ChatClient.MVVM.ViewModel;
using Microsoft.VisualBasic;
using System;
using System.Windows;
using System.Windows.Media.Media3D;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace ChatClient.Helpers
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

            // Iterates through each argument with support for bundled short flags like -teu
            for (int i = 0; i < args.Length; i++)
            {
                string rawArg = args[i];
                if (string.IsNullOrEmpty(rawArg))
                    continue;

                // Normalizes: accepts both Unix-style (--) and Windows-style (/)
                string arg = rawArg.StartsWith("/") ? "-" + rawArg.Substring(1) : rawArg;
                arg = arg.ToLowerInvariant();

                // Long options (start with --)
                if (arg.StartsWith("--"))
                {
                    switch (arg)
                    {
                        case "--nom":
                        case "--name":
                        case "--user":
                        case "--nick":
                        case "--pseudo":
                        case "--apodo":
                        case "--nickname":
                        case "--nombre":
                        case "--usuario":
                        case "--username":
                        case "--utilisateur":
                            if (i + 1 < args.Length)
                                usernameChosen = args[++i];
                            break;

                        case "--port":
                        case "--puerto":
                        case "--numport":
                        case "--listenport":
                        case "--portnumber":
                            if (i + 1 < args.Length && int.TryParse(args[i + 1], out var portNumberArgument))
                            {
                                Properties.Settings.Default.PortNumber = portNumberArgument;
                                i++;
                            }
                            break;

                        case "--dark":
                        case "--nuit":
                        case "--night":
                        case "--noche":
                        case "--oscuro":
                        case "--sombre":
                        case "--nocturne":
                        case "--nocturno":
                        case "--darkmode":
                            themeChosen = "dark";
                            break;

                        case "--dia":
                        case "--day":
                        case "--clair":
                        case "--claro":
                        case "--light":
                        case "--bright":
                        case "--lightmode":
                            themeChosen = "light";
                            break;
                        case "--en":
                        case "--eng":
                        case "--ingles":
                        case "--inglés":
                        case "--anglais":
                        case "--english":
                            langCodeChosen = "en";
                            break;

                        case "--fr":
                        case "--france":
                        case "--french":
                        case "--francés":
                        case "--frances":
                        case "--francais":
                        case "--français":
                            langCodeChosen = "fr";
                            break;

                        case "--es":
                        case "--sp":
                        case "--esp":
                        case "--espagnol":
                        case "--espanol":
                        case "--español":
                        case "--spanish":
                            langCodeChosen = "es";
                            break;

                        case "--enc":
                        case "--lock":
                        case "--crypt":
                        case "--crypté":
                        case "--crypte":
                        case "--crypto":
                        case "--crypted":
                        case "--secure":
                        case "--seguro":
                        case "--cifrado":
                        case "--chiffré":
                        case "--chiffre":
                        case "--encrypt":
                        case "--securise":
                        case "--securisé":
                        case "--encrypted":
                        case "--encryption":
                        case "--securemode":
                        case "--chiffrement":
                            enableEncryption = true;
                            break;

                        case "--tray":
                        case "--reduce":
                        case "--bandeja":
                        case "--systray":
                        case "--minimize":
                        case "--minimized":
                        case "--minimiser":
                        case "--minimizar":
                        case "--minimizado":
                            reduceInTray = true;
                            break;

                        case "--aide":
                        case "--ayuda":
                        case "--help":
                            showHelp = true;
                            break;

                        case "--about":
                        case "--info":
                        case "--infos":
                        case "--acerca":
                        case "--author":
                        case "--credits":
                        case "--licence":
                        case "--license":
                        case "--version":
                        case "--informacion":
                        case "--información":
                            showAbout = true;
                            break;

                        default:
                            break;
                    }
                    continue;
                }

                // Handles single-dash or slash-normalized flags and bundles
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
                                    // Tries to parse the port number
                                    if (int.TryParse(flagArgument, out var inputPort))
                                    {
                                        // Validates the port using the same logic as the UI
                                        bool isPortValid = MainViewModel.TrySavePort(inputPort);

                                        // Only saves if valid
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

            // Applies chosen localization
            if (!string.IsNullOrEmpty(langCodeChosen))
            {
                var supported = new[] { "en", "fr", "es"};
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

                Properties.Settings.Default.Save();
            }

            // Shows help and exits
            if (showHelp)
            {
                var about = new AboutWindow();
                about.ShowCommandLineArgumentsHelp();
                Environment.Exit(0);
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

            // Retrieves window and view model
            if (Application.Current.MainWindow is not MainWindow mainWindow ||
                mainWindow.viewModel is not MainViewModel viewModel)
            {
                ClientLogger.Log("MainWindow or MainViewModel not found during startup configuration.", ClientLogLevel.Warn);
                return;
            }

            // Persists encryption preference
            Properties.Settings.Default.UseEncryption = enableEncryption;
            Properties.Settings.Default.Save();

            // Updates VM
            viewModel.UseEncryption = enableEncryption;

            // If a username was chosen, we apply it and auto‑connect
            if (!string.IsNullOrEmpty(usernameChosen))
            {
                // Stores the username in the ViewModel
                viewModel.Username = usernameChosen;

                // Small helper to run the Connect/Disconnect command
                void ExecuteConnect()
                {
                    viewModel.ConnectDisconnectCommand?.Execute(null);
                }

                // If the window is already loaded, we can connect right now
                if (mainWindow.IsLoaded)
                {
                    ExecuteConnect();
                }
                else
                {
                    // Waits for the Loaded event before running the command.
                    RoutedEventHandler handler = null!;
                    handler = (_, _) =>
                    {
                        // Removes the handler so it runs only once
                        mainWindow.Loaded -= handler;

                        // Now the window is fully loaded, so we can connect
                        ExecuteConnect();
                    };

                    // Runs the handler once the window finishes loading
                    mainWindow.Loaded += handler;
                }
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



