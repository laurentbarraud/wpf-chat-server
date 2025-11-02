/// <file>ThemeManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 2nd, 2025</date>

using System;
using System.Windows;
using System.Windows.Media.Animation;

namespace chat_client.Helpers
{
    public static class ThemeManager
    {
        // URIs for the two theme files
        private static readonly Uri LightThemeUri = new Uri("Themes/LightTheme.xaml", UriKind.Relative);
        private static readonly Uri DarkThemeUri = new Uri("Themes/DarkTheme.xaml", UriKind.Relative);

        /// <summary>
        /// Applies the selected theme to the MainWindow with a fade animation.
        /// </summary>
        /// <param name="useDarkTheme">True to apply dark theme, false for light theme.</param>
        public static void ApplyTheme(bool useDarkTheme)
        {
            Properties.Settings.Default.AppTheme = useDarkTheme ? "dark" : "light";
            Properties.Settings.Default.Save();

            var targetWindow = Application.Current.MainWindow;
            if (targetWindow == null)
            {
                ApplyThemeWithoutAnimation(useDarkTheme);
                return;
            }

            var themeUri = useDarkTheme ? DarkThemeUri : LightThemeUri;

            // Creates a fade-out animation that transitions a UI element's opacity 
            // from fully visible (1.0) to fully transparent (0.0) over 150 milliseconds.
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(150));
            fadeOut.Completed += (_, _) =>
            {
                // Remove old theme dictionaries
                var existingThemes = Application.Current.Resources.MergedDictionaries
                    .Where(d => d.Source != null &&
                                (d.Source.Equals(LightThemeUri) || d.Source.Equals(DarkThemeUri)))
                    .ToList();

                foreach (var dict in existingThemes)
                    Application.Current.Resources.MergedDictionaries.Remove(dict);

                // Add new theme dictionary
                Application.Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });

                // Prepare fade-in animation
                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(150));

                // Apply watermark only after fade-in is fully completed
                fadeIn.Completed += (_, _) =>
                {
                    targetWindow.Dispatcher.Invoke(() =>
                    {
                        if (targetWindow is MainWindow mainWindow)
                        {
                            mainWindow.ApplyWatermarkImages();
                        }
                    });
                };

                // Start fade-in
                targetWindow.BeginAnimation(UIElement.OpacityProperty, fadeIn);
            };

            // Start fade-out
            targetWindow.BeginAnimation(UIElement.OpacityProperty, fadeOut);
        }

        /// <summary>
        /// Applies the selected theme immediately, without animation.
        /// </summary>
        /// <param name="useDarkTheme">True to apply dark theme, false for light theme.</param>
        private static void ApplyThemeWithoutAnimation(bool useDarkTheme)
        {
            var themeUri = useDarkTheme ? DarkThemeUri : LightThemeUri;

            // Removes any existing theme dictionaries
            var existingThemes = Application.Current.Resources.MergedDictionaries
                .Where(d => d.Source != null &&
                            (d.Source.Equals(LightThemeUri) || d.Source.Equals(DarkThemeUri)))
                .ToList();

            foreach (var dict in existingThemes)
                Application.Current.Resources.MergedDictionaries.Remove(dict);

            // Adds the new theme dictionary
            Application.Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });

            // Refreshes textBox backgrounds manually to reflect new theme
            var targetWindow = Application.Current.MainWindow;

            if (targetWindow is MainWindow mainWindow)
            {
                mainWindow.ApplyWatermarkImages();
            }
        }
    }
}

