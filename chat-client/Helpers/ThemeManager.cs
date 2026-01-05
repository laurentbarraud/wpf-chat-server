/// <file>ThemeManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 5th, 2026</date>

using System;
using System.Windows;
using System.Windows.Media.Animation;
using chat_client.MVVM.View;

namespace chat_client.Helpers
{
    public static class ThemeManager
    {
        /// <summary> URIs (Uniform Resource Identifiers) reference the relative paths for the files.  </summary>
        private static readonly Uri LightThemeUri = new Uri("Themes/LightTheme.xaml", UriKind.Relative);
        private static readonly Uri DarkThemeUri = new Uri("Themes/DarkTheme.xaml", UriKind.Relative);

        /// <summary>
        /// Applies the selected theme to the MainWindow with a fade animation.
        /// This method updates the persisted application theme setting,
        /// removes any existing theme dictionaries, and loads the new one.
        /// A fade-out/fade-in animation is used to provide a smooth visual transition.
        /// </summary>
        /// <param name="useDarkTheme">True to apply dark theme, false for light theme.</param>
        public static void ApplyTheme(bool useDarkTheme)
        {
            Properties.Settings.Default.AppTheme = useDarkTheme ? "dark" : "light";
            Properties.Settings.Default.Save();

            /// <remarks>
            /// In WPF, resources applied to Application.Current.MainWindow propagate through
            /// the visual tree to its child elements, so any secondary window (such as the 
            /// Settings dialog) opened under this parent automatically inherits 
            /// the updated theme accordingly.
            /// </remarks>
            var targetWindow = Application.Current.MainWindow;

            if (targetWindow == null)
            {
                ApplyThemeWithoutAnimation(useDarkTheme);
                return;
            }

            var themeUri = useDarkTheme ? DarkThemeUri : LightThemeUri;

            /// <summary> Creates a fade-out animation (opacity 1.0 → 0.0 over 150ms). </summary>
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(150));
            fadeOut.Completed += (_, _) =>
            {
                /// <summary> 
                /// Removes old theme dictionaries using a LINQ query, which iterates 
                /// over Application.Current.Resources.MergedDictionaries.
                /// The lambda checks that each dictionary has a valid URI and
                /// that it equals either LightThemeUri or DarkThemeUri.
                /// </summary>
                var existingThemes = Application.Current.Resources.MergedDictionaries
                    .Where(dict => dict.Source != null && (dict.Source.Equals(LightThemeUri) || 
                    dict.Source.Equals(DarkThemeUri))).ToList(); /// <remarks>
                                                                 /// .ToList() materializes
                                                                 /// the filtered sequence into a 
                                                                 /// List<ResourceDictionary> so that 
                                                                 /// it can be safely enumerated.
                                                                 /// </remarks>

                foreach (var dict in existingThemes)
                    Application.Current.Resources.MergedDictionaries.Remove(dict);

                /// <summary> Adds new theme dictionary </summary >
                Application.Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });
                
                /// <summary> 
                /// Prepares the fade‑in animation.
                /// The DoubleAnimation class animates a property. 
                /// In this case, opacity transitions from 0 (transparent) 
                /// to 1 (fully visible) over 150 milliseconds. 
                /// </summary>
                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(150));

                /// <summary> After fade-in completes, applies watermark images to the MainWindow. </summary>
                fadeIn.Completed += (_, _) =>
                {
                    targetWindow.Dispatcher.BeginInvoke(() =>
                    {
                        if (targetWindow is MainWindow mainWindow)
                        {
                            mainWindow.ApplyWatermarks();
                        }
                    });
                };

                /// <summary>
                /// Starts the fade‑in animation.
                /// </summary>
                /// <remarks>
                /// UIElement is the base class for most visual elements in WPF.
                /// It defines common properties and behaviors shared by controls, panels, and windows.
                /// Here, we reference UIElement.OpacityProperty, which is a dependency property
                /// controlling the transparency of any UI element.
                /// By animating this property on the MainWindow (targetWindow),
                /// the fade‑in effect applies to the entire window and, by extension,
                /// all of its child elements in the visual tree.
                /// </remarks>
                targetWindow.BeginAnimation(UIElement.OpacityProperty, fadeIn);
            };

            /// <summary> Starts fade-out </summary>
            targetWindow.BeginAnimation(UIElement.OpacityProperty, fadeOut);
        }

        /// <summary>
        /// Applies the selected theme immediately, without animation.
        /// This method removes any existing theme dictionaries,
        /// adds the new one, and refreshes UI elements such as watermark images.
        /// </summary>
        /// <param name="useDarkTheme">True to apply dark theme, false for light theme.</param>
        private static void ApplyThemeWithoutAnimation(bool useDarkTheme)
        {
            var themeUri = useDarkTheme ? DarkThemeUri : LightThemeUri;

            /// <summary> Removes any existing theme dictionaries (light or dark) with a lambda and LINQ </summary>
            var existingThemes = Application.Current.Resources.MergedDictionaries
                .Where(dict => dict.Source != null &&
                            (dict.Source.Equals(LightThemeUri) || dict.Source.Equals(DarkThemeUri)))
                .ToList();

            foreach (var dict in existingThemes)
                Application.Current.Resources.MergedDictionaries.Remove(dict);

            /// <summary> Adds the new theme dictionary to application resources. </summary>
            Application.Current.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = themeUri });

            /// <summary> Refreshes watermark images in the MainWindow to reflect the new theme. </summary>
            var targetWindow = Application.Current.MainWindow;
            if (targetWindow is MainWindow mainWindow)
            {
                mainWindow.ApplyWatermarks();
            }
        }
    }
}

