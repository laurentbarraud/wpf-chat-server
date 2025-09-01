/// <file>ThemeManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.6</version>
/// <date>September 1st, 2025</date>

using System;
using System.Linq;
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
        /// Applies the selected theme to the MainWindow form with a fade animation.
        /// </summary>
        /// <param name="useDarkTheme">True to apply dark theme, false for light theme.</param>
        public static void ApplyTheme(bool useDarkTheme)
        {
            var targetWindow = Application.Current.MainWindow;

            // If the window is not yet available, apply theme without animation
            if (targetWindow == null)
            {
                ApplyThemeWithoutAnimation(useDarkTheme);
                return;
            }

            var themeUri = useDarkTheme ? DarkThemeUri : LightThemeUri;

            // Fade out animation
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(150));
            fadeOut.Completed += (_, _) =>
            {
                // Remove existing theme dictionaries
                var existingThemes = Application.Current.Resources.MergedDictionaries
                    .Where(d => d.Source != null &&
                                (d.Source.Equals(LightThemeUri) || d.Source.Equals(DarkThemeUri)))
                    .ToList();

                foreach (var dict in existingThemes)
                    Application.Current.Resources.MergedDictionaries.Remove(dict);

                // Add the new theme
                Application.Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });

                // Fade in animation
                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(150));
                targetWindow.BeginAnimation(UIElement.OpacityProperty, fadeIn);

                // Force redraw after theme change
                targetWindow.InvalidateVisual();
                targetWindow.UpdateLayout();
            };

            targetWindow.BeginAnimation(UIElement.OpacityProperty, fadeOut);
        }

        /// <summary>
        /// Applies the selected theme immediately, without animation.
        /// </summary>
        /// <param name="useDarkTheme">True to apply dark theme, false for light theme.</param>
        private static void ApplyThemeWithoutAnimation(bool useDarkTheme)
        {
            var themeUri = useDarkTheme ? DarkThemeUri : LightThemeUri;

            var existingThemes = Application.Current.Resources.MergedDictionaries
                .Where(d => d.Source != null &&
                            (d.Source.Equals(LightThemeUri) || d.Source.Equals(DarkThemeUri)))
                .ToList();

            foreach (var dict in existingThemes)
                Application.Current.Resources.MergedDictionaries.Remove(dict);

            Application.Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });
        }
    }
}
