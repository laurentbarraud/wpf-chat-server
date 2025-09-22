/// <file>StartupConfigurator.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 22th, 2025</date>

using System;
using System.Linq;
using System.Windows;

namespace chat_client.Helpers
{
    /// <summary>
    /// Parses and applies command-line startup arguments to configure the chat client.
    /// Supports flexible aliases and applies settings for username, encryption, theme, language, port, tray behavior, and debug console.
    /// Automatically connects to localhost if username is provided.
    /// Designed for multi-client initialization and automated launch scenarios.
    /// </summary>
    public static class StartupConfigurator
    {
        /// <summary>
        /// Applies command-line arguments to initialize the client state.
        /// Supported flags:
        /// --username / -u / /username / -user / /user
        /// --port / -p / /port
        /// --theme / -t / /theme / --dark / /dark / --light / /light
        /// --language / -l / /language / --lang / /lang
        /// --encrypted / -e / /encrypted / /e
        /// --reduceInTray / -r / /reduceInTray / --reduce / /reduce
        /// --debug / -d / /debug
        /// --help / -h / -? / /help / /h / /?
        /// --about / /about // To-do: shows the About this software window
        /// </summary>
        /// <param name="args">Array of command-line arguments passed at startup.</param>
        public static void ApplyStartupArguments(string[] args)
        {
            if (args == null || args.Length == 0)
                return;

            string username = null;
            string theme = null;
            string language = null;
            int port = 7123;
            bool enableEncryption = false;
            bool reduceInTray = false;
            bool debugMode = false;
            bool showHelp = false;
            bool showAbout = false;

            // Parses all supported flags and their values
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

            // Displays help and exits
            if (showHelp)
            {
                Console.WriteLine("Chat Client Command-Line Options:");
                Console.WriteLine("  --username, -u, -user         Set username and auto-connect to localhost");
                Console.WriteLine("  --port, -p                    Set server port (default: 7123)");
                Console.WriteLine("  --theme, -t, --dark, --light Apply UI theme");
                Console.WriteLine("  --language, -l, --lang        Set UI language (en or fr)");
                Console.WriteLine("  --encrypted, -e               Enable message encryption");
                Console.WriteLine("  --reduceInTray, -r, --reduce Minimize to tray on startup");
                Console.WriteLine("  --debug, -d                   Show debug console");
                Console.WriteLine("  --about                       Show About window (coming soon)");
                Console.WriteLine("  --help, -h, -?                Show this help message");
                return;
            }

            // To-do: shows the About this software window
            if (showAbout)
            {
                Console.WriteLine("[Startup] About window requested. Feature not yet implemented.");
            }

            var mainWindow = Application.Current.MainWindow as MainWindow;
            var viewModel = mainWindow?.ViewModel;

            // Enables encryption if requested
            if (enableEncryption && viewModel != null)
            {
                Properties.Settings.Default.UseEncryption = true;
                viewModel.InitializeEncryption();
                Console.WriteLine("[Startup] Encryption enabled.");
            }

            // Applies theme (dark = true, light = false)
            if (!string.IsNullOrEmpty(theme))
            {
                bool isDark = theme.ToLower() == "dark";
                ThemeManager.ApplyTheme(isDark);
                Console.WriteLine($"[Startup] Theme applied: {(isDark ? "dark" : "light")}");
            }

            // Applies language if supported
            if (!string.IsNullOrEmpty(language))
            {
                var supportedLanguages = new[] { "en", "fr" };
                if (supportedLanguages.Contains(language.ToLower()))
                {
                    LocalizationManager.Initialize(language);
                    Console.WriteLine($"[Startup] Language set: {language}");
                }
                else
                {
                    Console.WriteLine($"[Startup] Unsupported language: {language}. Defaulting to 'en'.");
                    LocalizationManager.Initialize("en");
                }
            }

            // Applies reduce to tray setting
            if (reduceInTray)
            {
                Properties.Settings.Default.ReduceToTray = true;
                Console.WriteLine("[Startup] Reduce to tray enabled.");
            }

            // Shows debug console if requested
            if (debugMode)
            {
                ConsoleManager.Show(); // Requires ConsoleManager helper
                Console.WriteLine("[Startup] Debug console shown.");
            }

            // Applies username and triggers connection
            if (!string.IsNullOrEmpty(username) && mainWindow != null)
            {
                mainWindow.txtUsername.Text = username;
                Console.WriteLine($"[Startup] Username set: {username}");

                mainWindow.cmdConnectDisconnect_Click(new object(), new RoutedEventArgs());
            }

            Properties.Settings.Default.Save();
        }
    }
}
