/// <file>App.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>July 15th, 2026</date>

using ChatClient.Helpers;
using ChatClient.MVVM.View;
using ChatClient.MVVM.ViewModel;
using ChatClient.Properties;
using Hardcodet.Wpf.TaskbarNotification;
using System;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;

namespace ChatClient
{
    public partial class App : Application
    {
        private TaskbarIcon? trayIcon = null;

        /// <summary>
        /// Represents the tray menu item used to reopen the main application window.
        /// Typically bound to the system tray context menu for restoring visibility when minimized.
        /// </summary>
        public MenuItem? TrayMenuOpen { get; private set; }

        /// <summary>
        /// Represents the tray menu item used to exit the application.
        /// Bound to the system tray context menu to allow clean shutdown from the tray icon.
        /// </summary>
        public MenuItem? TrayMenuQuit { get; private set; }

        public static MainViewModel ViewModel { get; private set; } = null!;

        /// <summary>
        /// Application startup entry point.
        /// Initializes settings, culture, ViewModel,
        /// and displays the main window.
        /// </summary>
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Command-line arguments (excluding executable path)
            string[] cliArgs = Environment.GetCommandLineArgs().Skip(1).ToArray();

            // Applies startup flags
            StartupConfigurator.ApplyStartupArguments(cliArgs);


            // First launch: applies default settings
            if (string.IsNullOrWhiteSpace(Settings.Default.AppLanguageCode))
            {
                Settings.Default.AppLanguageCode = "en";
                Settings.Default.MessageInputFieldLeftOffsetPercent = 20.0;
                Settings.Default.Save();
            }

            // Global ViewModel
            App.ViewModel = new MainViewModel();
            App.ViewModel.PropertyChanged += ViewModel_PropertyChanged;
            App.ViewModel.ResetEncryptionPipelineAndUI();


            // Selects the correct window based on RawTextMode
            Window mainWindow = Settings.Default.RawTextMode
                ? new MainWindowLegacy()
                : new MainWindow();

            Application.Current.MainWindow = mainWindow;
            mainWindow.DataContext = App.ViewModel;

            // Window events
            mainWindow.StateChanged += MainWindow_StateChanged;
            mainWindow.Closing += MainWindow_Closing;

            mainWindow.Show();

            // Tray icon
            if (App.ViewModel.ReduceToTray)
            {
                InitializeTrayIcon();
            }

            // Language reload
            Settings.Default.Reload();
            string savedLanguageCode = Settings.Default.AppLanguageCode ?? "en";

            var cultureToApply = new CultureInfo(savedLanguageCode);
            Thread.CurrentThread.CurrentCulture = cultureToApply;
            Thread.CurrentThread.CurrentUICulture = cultureToApply;
            CultureInfo.DefaultThreadCurrentCulture = cultureToApply;
            CultureInfo.DefaultThreadCurrentUICulture = cultureToApply;

            LocalizationManager.InitializeLocalization(savedLanguageCode);

            // Global keyboard shortcuts
            // Registers a class-level handler for KeyDown events on all windows.
            // This makes all windows react to keyboard shortcuts, no matter where the focus is.
            // type = which class receives the shortcuts (here: every Window)
            // event = which keyboard event we listen to
            // handler = the function that runs when a key is pressed
            // handledEventsToo = true = catch the key even if another control already used it
            EventManager.RegisterClassHandler(typeof(Window), Keyboard.KeyDownEvent, 
                new KeyEventHandler(GlobalShortcutHandler), true);

#if DEBUG
            ClientLogger.IsDebugEnabled = true;
            ConsoleManager.Show();
            Console.OutputEncoding = System.Text.Encoding.UTF8;
#else
    if (Settings.Default.DebugMode)
    {
        ClientLogger.IsDebugEnabled = true;
        ConsoleManager.Show();
        Console.OutputEncoding = System.Text.Encoding.UTF8;
    }
#endif
        }

        /// <summary>
        /// Reduce to tray behavior: hides the main window and shows the tray icon when enabled.
        /// </summary>
        public void ApplyReduceToTray()
        {
            if (Application.Current.MainWindow == null)
            {
                return;
            }

            if (App.ViewModel.ReduceToTray)
            {
                InitializeTrayIcon();

                Application.Current.MainWindow.Hide();
                Application.Current.MainWindow.ShowInTaskbar = false;
            }
            else
            {
                Application.Current.MainWindow.Show();
                Application.Current.MainWindow.ShowInTaskbar = true;

                DisposeTrayIcon();
            }
        }

        /// <summary>
        /// Rebuilds and reattaches the tray icon context menu using the current language.
        /// Safe to call multiple times. Ensures the right-click handler is always attached.
        /// </summary>
        public void ApplyTrayMenuLocalization()
        {
            if (trayIcon == null)
            {
                return;
            }

            // Rebuilds the localized context menu
            trayIcon.ContextMenu = BuildLocalizedTrayMenu();

            // Reattaches right-click handler
            trayIcon.TrayRightMouseUp -= TrayIcon_RightClickHandler;
            trayIcon.TrayRightMouseUp += TrayIcon_RightClickHandler;
        }

        /// <summary>
        /// Builds a localized tray context menu.
        /// </summary>
        /// <returns>ContextMenu instance.</returns>
        private ContextMenu BuildLocalizedTrayMenu()
        {
            var contextMenu = new ContextMenu();

            TrayMenuOpen = new MenuItem
            {
                Header = LocalizationManager.GetString("TrayOpenLabel")
            };
            TrayMenuOpen.Click += TrayMenu_Open_Click;

            TrayMenuQuit = new MenuItem
            {
                Header = LocalizationManager.GetString("TrayQuitLabel")
            };
            TrayMenuQuit.Click += TrayMenu_Quit_Click;

            contextMenu.Items.Add(TrayMenuOpen);
            contextMenu.Items.Add(TrayMenuQuit);

            return contextMenu;
        }

        /// <summary>
        /// Disposes the tray icon if it exists.
        /// </summary>
        public void DisposeTrayIcon()
        {
            try
            {
                if (trayIcon != null)
                {
                    trayIcon.Dispose();
                    trayIcon = null;
                }
            }
            catch
            {
            }
        }

        /// <summary>
        /// Handles global keyboard shortcuts for the whole app.
        /// Works even when another window or control has focus.
        /// </summary>
        private void GlobalShortcutHandler(object sender, KeyEventArgs e)
        {
            if (Application.Current.MainWindow == null || App.ViewModel == null)
            {
                return;
            }

            // Ctrl+T : toggle theme (modern window only)
            if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.T)
            {
                if (Application.Current.MainWindow is MainWindow modern)
                {
                    modern.ThemeToggle.IsChecked = !modern.ThemeToggle.IsChecked;
                    modern.ThemeToggle.Command?.Execute(modern.ThemeToggle.IsChecked ?? false);
                }

                e.Handled = true;
                return;
            }

            // Ctrl+E : toggle encryption (global)
            if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.E)
            {
                App.ViewModel.EncryptMessages = !App.ViewModel.EncryptMessages;
                e.Handled = true;
                return;
            }

            // Ctrl+K / Ctrl+M : toggle key monitor
            if (Keyboard.Modifiers == ModifierKeys.Control &&
                (e.Key == Key.K || e.Key == Key.M))
            {
                // If the modern window is active
                if (Application.Current.MainWindow is MainWindow modern)
                {
                    modern.ToggleMonitorWindow();
                }

                // If the legacy window is active
                if (Application.Current.MainWindow is MainWindowLegacy legacy)
                {
                    legacy.ToggleMonitorWindow();
                }

                e.Handled = true;
                return;
            }
        }

        /// <summary>
        /// Initializes the tray icon with its localized context menu and event handlers.
        /// Ensures the menu is attached only once and handles right-click behavior.
        /// </summary>
        public void InitializeTrayIcon()
        {
            if (trayIcon == null)
            {
                return;
            }

            // Attaches localized context menu
            trayIcon.ContextMenu = BuildLocalizedTrayMenu();

            // Ensures right-click handler is attached only once
            trayIcon.TrayRightMouseUp -= TrayIcon_RightClickHandler;
            trayIcon.TrayRightMouseUp += TrayIcon_RightClickHandler;

            // Ensures double-click restores the window
            trayIcon.TrayMouseDoubleClick -= TrayIcon_TrayMouseDoubleClick;
            trayIcon.TrayMouseDoubleClick += TrayIcon_TrayMouseDoubleClick;

            trayIcon.Visibility = Visibility.Visible;
        }

        private void MainWindow_Closing(object? sender, CancelEventArgs e)
        {
            if (App.ViewModel.ReduceToTray)
            {
                e.Cancel = true;
                ApplyReduceToTray();
            }
        }


        private void MainWindow_StateChanged(object? sender, EventArgs e)
        {
            if (Application.Current.MainWindow.WindowState == WindowState.Minimized)
            {
                ApplyReduceToTray();
            }
        }

        // Cleanly disposes resources and unsubscribes from events on application exit.
        protected override void OnExit(ExitEventArgs e)
        {
            if (MainWindow != null)
            {
                MainWindow.StateChanged -= MainWindow_StateChanged;
                MainWindow.Closing -= MainWindow_Closing;
            }

            base.OnExit(e);
        }


        /// <summary>
        /// Restores the main window from the system tray when the user clicks the tray icon or selects "Open" from the context menu.
        /// </summary>
        public void RestoreFromTray()
        {
            if (trayIcon != null)
            {
                trayIcon.Visibility = Visibility.Collapsed;
            }

            if (Application.Current.MainWindow != null)
            {
                Application.Current.MainWindow.Show();
                Application.Current.MainWindow.WindowState = WindowState.Normal;
                Application.Current.MainWindow.ShowInTaskbar = true;
            }
        }

        /// <summary>
        /// Replaces the currently visible window with a new one.
        /// Preserves size, position, window state, and the ViewModel.
        /// </summary>
        public static void SwitchWindow(Window oldWindow, Window newWindow)
        {
            // Copies size and position
            newWindow.Left = oldWindow.Left;
            newWindow.Top = oldWindow.Top;
            newWindow.Width = oldWindow.Width;
            newWindow.Height = oldWindow.Height;

            // Copies window state (Normal / Maximized)
            newWindow.WindowState = oldWindow.WindowState;

            // Copies the global ViewModel reference
            newWindow.DataContext = App.ViewModel;

            newWindow.Show();
            oldWindow.Close();

            // Updates the main window reference
            Application.Current.MainWindow = newWindow;
        }

        /// <summary> 
        /// Handles right-click on the tray icon by opening the localized context menu 
        /// at the current mouse position.
        /// </summary> 
        private void TrayIcon_RightClickHandler(object sender, RoutedEventArgs e)
        {
            if (trayIcon?.ContextMenu == null)
            {
                return;
            }

            trayIcon.ContextMenu.PlacementTarget = Application.Current.MainWindow;
            trayIcon.ContextMenu.Placement = PlacementMode.MousePoint;
            trayIcon.ContextMenu.IsOpen = true;
        }

        private void TrayIcon_TrayMouseDoubleClick(object sender, RoutedEventArgs e)
        {
           RestoreFromTray();
        }

        /// <summary>
        /// Handles the "Open" action from the tray context menu.
        /// Hides the tray icon and restores the main window to its normal state.
        /// Ensures the window is visible and reappears in the taskbar.
        /// </summary>
        public void TrayMenu_Open_Click(object sender, RoutedEventArgs e)
        {
            RestoreFromTray();
        }

        public void TrayMenu_Quit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }


        /// <summary>
        /// This event handler listens for changes in the ViewModel properties.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(MainViewModel.ReduceToTray))
            {
                InitializeTrayIcon();
            }
        }
    }
}

