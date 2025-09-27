/// <file>LocalizationManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 27th, 2025</date>

using System.Resources;
using System.Globalization;
using System.Diagnostics;
using System.Threading;
using System.Windows;
using chat_client.Resources;
using chat_client.MVVM.View;

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides centralized localization support for the application.
    /// Loads resource strings based on the selected language and updates UI elements accordingly.
    /// </summary>
    public static class LocalizationManager
    {
        /// <summary>
        /// Holds the ResourceManager for retrieving localized strings.
        /// </summary>
        public static ResourceManager ResourceManager { get; private set; }

        /// <summary>
        /// Holds the current CultureInfo used for string lookups.
        /// </summary>
        public static CultureInfo CurrentCulture { get; private set; }

        static LocalizationManager()
        {
            // Initializes ResourceManager from the auto-generated Strings class
            ResourceManager = Strings.ResourceManager;
            // Sets the default culture to the current UI culture
            CurrentCulture = CultureInfo.CurrentUICulture;
        }

        /// <summary>
        /// Retrieves and formats a localized string by replacing escaped newline and tab markers.
        /// </summary>
        /// <param name="key">The resource key to look up.</param>
        /// <returns>The formatted localized string or a fallback marker if not found.</returns>
        public static string GetFormattedString(string key)
        {
            string raw = GetString(key);
            return raw.Replace("\\n", "\n")
                      .Replace("\\t", "\t");
        }

        /// <summary>
        /// Retrieves a localized string from the resource file using the specified key.
        /// Returns a fallback marker if the key is missing or the lookup fails.
        /// </summary>
        /// <param name="key">The resource key to look up.</param>
        /// <returns>The localized string or a fallback marker if not found.</returns>
        public static string GetString(string key)
        {
            // Validates that key is not null or whitespace
            if (string.IsNullOrWhiteSpace(key))
                return string.Empty;

            // Returns fallback marker if ResourceManager or CurrentCulture is uninitialized
            if (ResourceManager == null || CurrentCulture == null)
                return $"[[{key}]]";

            try
            {
                // Attempts to retrieve the localized value
                string value = ResourceManager.GetString(key, CurrentCulture) ?? string.Empty;

                // Returns fallback marker if retrieved value is null or whitespace
                if (string.IsNullOrWhiteSpace(value))
                    return $"[[{key}]]";

                return value;
            }
            catch (MissingManifestResourceException ex)
            {
                // Logs missing resource exceptions for troubleshooting
                Debug.WriteLine($"Localization error: missing resource for key '{key}' — {ex.Message}");
                return $"[[{key}]]";
            }
            catch (Exception ex)
            {
                // Logs unexpected exceptions without interrupting application flow
                Debug.WriteLine($"Unexpected localization error for key '{key}' — {ex.Message}");
                return $"[[{key}]]";
            }
        }

        /// <summary>
        /// Initializes the localization system with the specified language code.
        /// </summary>
        /// <param name="languageCode">The culture code to set (e.g., "en" or "fr").</param>
        public static void Initialize(string languageCode)
        {
            // Sets CurrentCulture to the new language code
            CurrentCulture = new CultureInfo(languageCode);

            // Updates thread UI culture settings
            Thread.CurrentThread.CurrentUICulture = CurrentCulture;
            CultureInfo.DefaultThreadCurrentUICulture = CurrentCulture;

            // Re-initializes ResourceManager to account for culture change
            ResourceManager = Strings.ResourceManager;

            // Applies localized strings to all open windows
            UpdateLocalizedUI();
        }

        /// <summary>
        /// Updates UI elements across all open windows to reflect the current culture.
        /// </summary>
        public static void UpdateLocalizedUI()
        {
            // Iterates through each open window in the application
            foreach (Window window in Application.Current.Windows)
            {
                if (window is SettingsWindow settings)
                {
                    // Updates labels in the SettingsWindow
                    settings.UseCustomPortLabel.Content = GetString("UseCustomPortLabel");
                    settings.ReduceToTrayLabel.Content = GetString("ReduceToTrayLabel");
                    settings.UseEncryptionLabel.Content = GetString("UseEncryptionLabel");
                    settings.AppLanguageLabel.Content = GetString("AppLanguageLabel");
                    settings.AboutTextBlock.Text = GetString("About");
                }
                else if (window is MainWindow mainWindow)
                {
                    // Updates dynamic UI elements in MainWindow
                    mainWindow.UpdateConnectButtonText();
                    mainWindow.ApplyWatermarkImages();

                    // Updates tooltip texts
                    mainWindow.CmdScrollLeft.ToolTip = GetString("ScrollLeftTooltip");
                    mainWindow.CmdScrollRight.ToolTip = GetString("ScrollRightTooltip");
                    mainWindow.CmdSettings.ToolTip = GetString("Settings");

                    // Updates window title to include localized "Connected" status
                    mainWindow.Title = $"WPF chat client - {GetString("Connected")}";

                    // Updates tray menu headers if they exist
                    mainWindow.TrayMenuOpen.Header = GetString("TrayOpen");
                    mainWindow.TrayMenuQuit.Header = GetString("TrayQuit");
                }
            }
        }
    }
}

