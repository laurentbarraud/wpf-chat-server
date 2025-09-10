/// <file>ThemeManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 10th, 2025</date>

using chat_client.Helpers;
using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
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
            var targetWindow = Application.Current.MainWindow;
            if (targetWindow == null)
            {
                ApplyThemeWithoutAnimation(useDarkTheme);
                return;
            }

            var themeUri = useDarkTheme ? DarkThemeUri : LightThemeUri;

            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(150));
            fadeOut.Completed += (_, _) =>
            {
                // Removes old theme dictionaries from Application-level resources
                var existingThemes = Application.Current.Resources.MergedDictionaries
                    .Where(d => d.Source != null &&
                                (d.Source.Equals(LightThemeUri) || d.Source.Equals(DarkThemeUri)))
                    .ToList();

                foreach (var dict in existingThemes)
                    Application.Current.Resources.MergedDictionaries.Remove(dict);

                // Adds new theme dictionary to Application-level resources
                Application.Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });

                // Fades in and refreshes watermark images
                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(150));
                fadeIn.Completed += (_, _) =>
                {
                    if (targetWindow is MainWindow mainWindow)
                    {
                        mainWindow.ApplyWatermarkImages();
                    }
                };


                targetWindow.BeginAnimation(UIElement.OpacityProperty, fadeIn);
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

