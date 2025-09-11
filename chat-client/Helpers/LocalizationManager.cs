/// <file>LocalizationManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 11th, 2025</date>

using chat_client.MVVM.View;
using System;
using System.Collections.Generic;
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
        public static ResourceManager ResourceManager { get; private set; }
        public static CultureInfo CurrentCulture { get; private set; }

        /// <summary>
        /// Initializes the localization system with the specified language code.
        /// </summary>
        /// <param name="languageCode">A valid language code ("en" or "fr").</param>
        public static void Initialize(string languageCode)
        {
            CurrentCulture = new CultureInfo(languageCode);
            ResourceManager = new ResourceManager("chat_client.Resources.Strings", typeof(LocalizationManager).Assembly);
        }

        /// <summary>
        /// Retrieves a localized string from the resource file using the specified key.
        /// </summary>
        /// <param name="key">The resource key to look up.</param>
        /// <returns>The localized string corresponding to the key, or null if not found.</returns>
        public static string GetString(string key)
        {
            return ResourceManager.GetString(key, CurrentCulture);
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
                }
                else if (window is MainWindow mainWindow)
                {
                    mainWindow.cmdConnectDisconnect.Content = GetString("ConnectButton");
                    mainWindow.ApplyWatermarkImages();
                }
            }
        }
    }
}
