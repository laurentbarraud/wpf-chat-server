/// <file>LocalizationManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 13th, 2025</date>

using chat_client.MVVM.View;
using chat_client.Net;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Resources;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides centralized localization support for the application.
    /// Loads resource strings based on the selected language and updates UI elements accordingly.
    /// </summary>
    public static class LocalizationManager
    {
        public static ResourceManager _ResourceManager { get; private set; }

        public static CultureInfo CurrentCulture { get; private set; }

        /// <summary>
        /// Initializes the localization system with the specified language code.
        /// </summary>
        /// <param name="languageCode">A valid language code ("en" or "fr").</param>
        public static void Initialize(string languageCode)
        {
            CurrentCulture = new CultureInfo(languageCode);

            // Force thread culture
            Thread.CurrentThread.CurrentUICulture = CurrentCulture;
            CultureInfo.DefaultThreadCurrentUICulture = CurrentCulture;

            _ResourceManager = new ResourceManager("chat_client.Resources.Strings", typeof(LocalizationManager).Assembly);


            // Force UI refresh
            UpdateLocalizedUI();
        }
        /// <summary>
        /// Retrieves a localized string from the resource file using the specified key.
        /// Returns the key itself if the resource manager is not initialized,
        /// the culture is missing, or the key is not found.
        /// </summary>
        /// <param name="key">The resource key to look up.</param>
        /// <returns>The localized string corresponding to the key, or the key itself if not found.</returns>
        public static string GetString(string key)
        {
            // Validate input
            if (string.IsNullOrWhiteSpace(key))
                return string.Empty;

            // Ensure localization system is initialized
            if (_ResourceManager == null || CurrentCulture == null)
                return $"[[{key}]]"; // Fallback marker for debugging

            try
            {
                string value = _ResourceManager.GetString(key, CurrentCulture);

                // Return fallback if value is missing or empty
                return string.IsNullOrWhiteSpace(value) ? $"[[{key}]]" : value;
            }
            catch (MissingManifestResourceException ex)
            {
                Debug.WriteLine($"Localization error: missing resource for key '{key}' — {ex.Message}");
                return $"[[{key}]]";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Unexpected localization error for key '{key}' — {ex.Message}");
                return $"[[{key}]]";
            }
        }

        /// <summary>
        /// Applies localized strings to UI elements across all open windows.
        /// This method updates labels and buttons based on the current language setting.
        /// </summary>
        public static void UpdateLocalizedUI()
        {
            foreach (Window window in Application.Current.Windows)
            {
                if (window is SettingsWindow settings)
                {
                    settings.UseCustomPortLabel.Content = GetString("UseCustomPortLabel");
                    settings.ReduceInTrayLabel.Content = GetString("ReduceInTrayLabel");
                    settings.UseEncryptionLabel.Content = GetString("UseEncryptionLabel");
                    settings.AppLanguageLabel.Content = GetString("AppLanguageLabel");
                    settings.lblAbout.Content = GetString("About");
                }
                else if (window is MainWindow mainWindow)
                {
                    mainWindow.UpdateConnectButtonText();
                    mainWindow.ApplyWatermarkImages();

                    // Update tray menu labels
                    if (mainWindow.TrayMenuOpen != null)
                        mainWindow.TrayMenuOpen.Header = GetString("TrayOpen");

                    if (mainWindow.TrayMenuQuit != null)
                        mainWindow.TrayMenuQuit.Header = GetString("TrayQuit");

                    // Update encryption banner text
                    mainWindow.popupText.Text = GetString("EncryptionEnabled");
                }
            }
        }
    }
}
