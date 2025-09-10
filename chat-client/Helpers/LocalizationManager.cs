/// <file>LocalizationManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 10th, 2025</date>

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
    /// Manages localization by loading resource files based on selected language.
    /// </summary>
    public static class LocalizationManager
    {
        public static ResourceManager ResourceManager { get; private set; }
        public static CultureInfo CurrentCulture { get; private set; }

        public static void Initialize(string languageCode)
        {
            CurrentCulture = new CultureInfo(languageCode);
            ResourceManager = new ResourceManager("chat_client.Resources.Strings", typeof(LocalizationManager).Assembly);
        }

        /// <summary>
        /// Returns the localized string for the given key.
        /// </summary>
        public static string GetString(string key)
        {
            return ResourceManager.GetString(key, CurrentCulture);
        }

        public static void UpdateLocalizedUI(Window targetWindow)
        {
            if (targetWindow == null)
            {
                return;
            }

            // SettingsWindow
            if (targetWindow is SettingsWindow settings)
            {
                settings.UseCustomPortLabel.Content = GetString("UseCustomPortLabel");
                settings.ReduceInTrayLabel.Content = GetString("ReduceInTrayLabel");
                settings.UseEncryptionLabel.Content = GetString("UseEncryptionLabel");
                settings.AppLanguageLabel.Content = GetString("AppLanguageLabel");
            }

            // MainWindow
            else if (targetWindow is MainWindow main)
            {
                main.cmdConnectDisconnect.Content = GetString("ConnectButton");
            }
        }
    }
}
