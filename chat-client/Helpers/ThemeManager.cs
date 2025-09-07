/// <file>ThemeManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.9</version>
/// <date>September 7th, 2025</date>
/// 
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

            // If the window is not yet available, applies theme without animation
            if (targetWindow == null)
            {
                ApplyThemeWithoutAnimation(useDarkTheme);
                return;
            }

            var themeUri = useDarkTheme ? DarkThemeUri : LightThemeUri;

            // Fades out animation before switching theme
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(150));
            fadeOut.Completed += (_, _) =>
            {
                // Removes any existing theme dictionaries
                var existingThemes = Application.Current.Resources.MergedDictionaries
                    .Where(d => d.Source != null &&
                                (d.Source.Equals(LightThemeUri) || d.Source.Equals(DarkThemeUri)))
                    .ToList();

                foreach (var dict in existingThemes)
                    Application.Current.Resources.MergedDictionaries.Remove(dict);

                // Add the new theme dictionary
                Application.Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });

                // Refreshes TextBox backgrounds manually to reflect new theme
                if (targetWindow.FindName("txtUsername") is TextBox txtUsername)
                {
                    txtUsername.Background = (Brush)Application.Current.Resources["txtUsername_background"];
                    
                    if (!string.IsNullOrEmpty(txtUsername.Text))
                    {
                        txtUsername.Background = null;
                    }
                }

                if (targetWindow.FindName("txtIPAddress") is TextBox txtIPAddress)
                {
                    txtIPAddress.Background = (Brush)Application.Current.Resources["txtIPAddress_background"];
                    
                    if (!string.IsNullOrEmpty(txtIPAddress.Text))
                    {
                        txtIPAddress.Background = null;
                    }
                }

                // Fades in animation after theme switch
                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(150));
                targetWindow.BeginAnimation(UIElement.OpacityProperty, fadeIn);

                // Forces redraw of the window
                targetWindow.InvalidateVisual();
                targetWindow.UpdateLayout();
            };

            // Starts fade out
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

            if (targetWindow != null)
            {
                if (targetWindow.FindName("txtUsername") is TextBox txtUsername)
                    txtUsername.Background = (Brush)Application.Current.Resources["txtUsername_background"];

                if (targetWindow.FindName("txtIPAddress") is TextBox txtIPAddress)
                    txtIPAddress.Background = (Brush)Application.Current.Resources["txtIPAddress_background"];
            }
        }
    }
}
