/// <file>App.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 3rd, 2026</date>

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

            // Applies all other startup flags
            StartupConfigurator.ApplyStartupArguments(args);
            
            // Detects if a language was explicitly requested via command-line
            bool languageForcedByArgs = args.Any(a => a.Equals("--fr", StringComparison.OrdinalIgnoreCase) 
            || a.Equals("--french", StringComparison.OrdinalIgnoreCase) 
            || a.Equals("--es", StringComparison.OrdinalIgnoreCase) 
            || a.Equals("--esp", StringComparison.OrdinalIgnoreCase) 
            || a.Equals("--spanish", StringComparison.OrdinalIgnoreCase) 
            || a.Equals("--en", StringComparison.OrdinalIgnoreCase) 
            || a.Equals("--english", StringComparison.OrdinalIgnoreCase) );

            // Applies default settings on first launch
            if (string.IsNullOrWhiteSpace(Settings.Default.AppLanguageCode))
            {
                // Default language
                Settings.Default.AppLanguageCode = "en";

                // Default horizontal offset (20%) for a more balanced layout
                Settings.Default.MessageInputFieldLeftOffsetPercent = 20.0;
                Settings.Default.Save();

                // After the main window is created, sets the input field row to minimum height
                this.Dispatcher.InvokeAsync(() =>
                {
                    if (Application.Current.MainWindow is MainWindow mainWindow)
                    {
                        // Sets RowBottomRight to its minimum height
                        mainWindow.RowBottomRight.Height = new GridLength(mainWindow.RowBottomRight.MinHeight, GridUnitType.Pixel);
                    }
                });
            }

            // Creates and displays the main window
            var mainWindow = new MainWindow();
            Application.Current.MainWindow = mainWindow;
            mainWindow.Show();

            // Re-reads the language after StartupConfigurator has applied command-line flags
            Settings.Default.Reload();
            string languageCodeSaved = Settings.Default.AppLanguageCode ?? "en";

            // Culture & localization setup
            var cultureToApply = new CultureInfo(languageCodeSaved);

            Thread.CurrentThread.CurrentCulture = cultureToApply;
            Thread.CurrentThread.CurrentUICulture = cultureToApply;
            CultureInfo.DefaultThreadCurrentCulture = cultureToApply;
            CultureInfo.DefaultThreadCurrentUICulture = cultureToApply;

            LocalizationManager.InitializeLocalization(languageCodeSaved);

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
            if (Settings.Default.DebugMode)
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
