/// <file>App.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 15th, 2026</date>

using ChatClient.Helpers;
using ChatClient.Properties;
using ChatClient.MVVM.View;
using ChatClient.MVVM.ViewModel;
using System;
using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Controls;

namespace ChatClient
{
    public partial class App : Application
    {
        /// <summary>
        /// Application startup entry point.
        /// 
        /// Responsibilities:
        /// • Parses command-line arguments
        /// • Applies startup configuration flags
        /// • Initializes culture and localization
        /// • Creates and displays the main window
        /// • Registers global keyboard shortcuts for all windows
        /// • Optionally opens the debug console depending on build mode and flags
        /// 
        /// This method runs before any window is shown and prepares the
        /// application environment for the entire session.
        /// </summary>
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Collects all command-line arguments (skipping the executable path)
            string[] args = Environment.GetCommandLineArgs().Skip(1).ToArray();

            // Detects debug/console flags
            bool debugMode = args.Any(arg =>
                arg.Equals("--debug", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("--console", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("-d", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("-c", StringComparison.OrdinalIgnoreCase));

            // Applies all other startup flags
            StartupConfigurator.ApplyStartupArguments(args);

            // Culture & localization setup
            string languageCodeSaved = Settings.Default.AppLanguageCode ?? "en";
            var cultureToApply = new CultureInfo(languageCodeSaved);

            Thread.CurrentThread.CurrentCulture = cultureToApply;
            Thread.CurrentThread.CurrentUICulture = cultureToApply;
            CultureInfo.DefaultThreadCurrentCulture = cultureToApply;
            CultureInfo.DefaultThreadCurrentUICulture = cultureToApply;

            LocalizationManager.InitializeLocalization(languageCodeSaved);

            // Creates and displays the main window
            var mainWindow = new MainWindow();
            Application.Current.MainWindow = mainWindow;
            mainWindow.Show();

            // Registers global keyboard shortcuts for all windows
            EventManager.RegisterClassHandler(
                typeof(Window),
                Keyboard.PreviewKeyDownEvent,
                new KeyEventHandler(GlobalShortcutHandler));

            #if DEBUG
            // Debug build: always show console when running under Visual Studio
            ClientLogger.IsDebugEnabled = true;
            ConsoleManager.Show();
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            
            #else
            // Release build: show console only if explicitly requested
            if (debugMode)
            {
                ClientLogger.IsDebugEnabled = true;
                ConsoleManager.Show();
                Console.OutputEncoding = System.Text.Encoding.UTF8;
            }
            #endif
        }

        /// <summary>
        /// Global keyboard shortcut handler.
        /// Ensures shortcuts work even when secondary windows
        /// (such as the Settings window) are focused.
        /// </summary>
        private void GlobalShortcutHandler(object sender, KeyEventArgs e)
        {
            var mainWindow = Application.Current.MainWindow as MainWindow;
            var viewModel = mainWindow?.DataContext as MainViewModel;

            if (mainWindow == null)
            {
                return;
            }

            // Theme toggle 
            if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.T)
            {
                mainWindow.ThemeToggle.IsChecked = !mainWindow.ThemeToggle.IsChecked;
                mainWindow.ThemeToggle.Command?.Execute(mainWindow.ThemeToggle.IsChecked ?? false);

                e.Handled = true;
                return;
            }

            // Encryption toggle 
            if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.E)
            {
                if (viewModel != null)
                    viewModel.UseEncryption = !viewModel.UseEncryption;

                e.Handled = true;
                return;
            }

            // Monitor button
            if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.K)
            {
                mainWindow.ToggleMonitorWindow();

                e.Handled = true;
                return;
            }
        }
    }
}
