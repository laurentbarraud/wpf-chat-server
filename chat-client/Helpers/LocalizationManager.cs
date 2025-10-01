﻿/// <file>LocalizationManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 1st, 2025</date>

using System;
using System;
using System.Resources;
using System.Globalization;
using System.Reflection;
using System.Diagnostics;
using System.Threading;
using System.Windows;
using chat_client.MVVM.View;

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides centralized localization support for the application.
    /// Loads resource strings from embedded .resx files based on the current culture,
    /// and applies them to UI elements across open windows.
    /// </summary>
    public static class LocalizationManager
    {
        /// <summary>
        /// Manages lookup of localized strings from the embedded Strings.resx resources.
        /// </summary>
        public static ResourceManager ResourceManager { get; private set; }

        /// <summary>
        /// The CultureInfo used for all string lookups.
        /// </summary>
        public static CultureInfo CurrentCulture { get; private set; }

        static LocalizationManager()
        {
            // Point to the base-name of your Strings.resx in this assembly
            ResourceManager = new ResourceManager("chat_client.Resources.Strings",
                                                  Assembly.GetExecutingAssembly());
            // Default to the system UI culture at startup
            CurrentCulture = CultureInfo.CurrentUICulture;
        }

        /// <summary>
        /// Retrieves and formats a localized string by replacing escaped newline and tab markers.
        /// </summary>
        /// <param name="key">The resource key to look up.</param>
        /// <returns>
        /// The formatted localized string, or a fallback marker [[key]] if missing.
        /// </returns>
        public static string GetFormattedString(string key)
        {
            var raw = GetString(key);
            return raw
                .Replace("\\n", "\n")
                .Replace("\\t", "\t");
        }

        /// <summary>
        /// Retrieves a localized string from the resource file using the specified key.
        /// Returns [[key]] if the key is missing or if any error occurs.
        /// </summary>
        /// <param name="key">The resource key to look up.</param>
        /// <returns>The localized string or a fallback marker.</returns>
        public static string GetString(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                return string.Empty;

            if (ResourceManager == null || CurrentCulture == null)
                return $"[[{key}]]";

            try
            {
                var value = ResourceManager.GetString(key, CurrentCulture);
                return string.IsNullOrWhiteSpace(value)
                     ? $"[[{key}]]"
                     : value;
            }
            catch (MissingManifestResourceException mex)
            {
                Debug.WriteLine($"Localization error: missing resource for key '{key}' — {mex.Message}");
                return $"[[{key}]]";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Unexpected localization error for key '{key}' — {ex.Message}");
                return $"[[{key}]]";
            }
        }

        /// <summary>
        /// Initializes the localization system to use the specified culture code (e.g., "en", "fr").
        /// Updates CurrentCulture, reloads the ResourceManager, and refreshes all open windows.
        /// </summary>
        /// <param name="languageCode">The culture code to apply.</param>
        public static void Initialize(string languageCode)
        {
            CurrentCulture = new CultureInfo(languageCode);
            Thread.CurrentThread.CurrentUICulture = CurrentCulture;
            CultureInfo.DefaultThreadCurrentUICulture = CurrentCulture;

            // Reset ResourceManager in case satellite assemblies are now loaded
            ResourceManager = new ResourceManager("chat_client.Resources.Strings",
                                                  Assembly.GetExecutingAssembly());

            UpdateLocalizedUI();
        }

        /// <summary>
        /// Applies the current culture’s localized strings to all open SettingsWindow and MainWindow instances.
        /// </summary>
        public static void UpdateLocalizedUI()
        {
            foreach (Window window in Application.Current.Windows)
            {
                if (window is SettingsWindow settings)
                {
                    settings.UseCustomPortLabel.Content = GetString("UseCustomPortLabel");
                    settings.ReduceToTrayLabel.Content = GetString("ReduceToTrayLabel");
                    settings.UseEncryptionLabel.Content = GetString("UseEncryptionLabel");
                    settings.AppLanguageLabel.Content = GetString("AppLanguageLabel");
                    settings.AboutTextBlock.Text = GetString("About");
                }
                else if (window is MainWindow mainWindow)
                {
                    mainWindow.UpdateConnectButtonText();
                    mainWindow.ApplyWatermarkImages();

                    mainWindow.CmdScrollLeft.ToolTip = GetString("ScrollLeftTooltip");
                    mainWindow.CmdScrollRight.ToolTip = GetString("ScrollRightTooltip");
                    mainWindow.CmdSettings.ToolTip = GetString("Settings");

                    mainWindow.Title = $"WPF chat client - {GetString("Connected")}";

                    if (mainWindow.TrayMenuOpen != null)
                        mainWindow.TrayMenuOpen.Header = GetString("TrayOpen");

                    if (mainWindow.TrayMenuQuit != null)
                        mainWindow.TrayMenuQuit.Header = GetString("TrayQuit");
                }
            }
        }
    }
}

