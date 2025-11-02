/// <file>LocalizationManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 2nd, 2025</date>

using System;
using System.Diagnostics;
using System.Globalization;
using System.Resources;
using System.Reflection;
using System.Threading;

namespace chat_server.Helpers
{
    /// <summary>
    /// Provides centralized localization support for the console server.
    /// Loads .resx resources based on the current culture and
    /// returns a fail-safe fallback if a key is missing or an error occurs.
    /// </summary>
    public static class LocalizationManager
    {
        // Holds the ResourceManager for looking up localized strings
        private static ResourceManager _resourceManager = null!;

        // Holds the CultureInfo used for lookups
        private static CultureInfo _currentCulture = CultureInfo.InvariantCulture;

        /// <summary>
        /// Retrieves a localized string by key.
        /// If the key is missing or an error occurs, returns [[key]] as a fallback.
        /// </summary>
        /// <param name="key">The resource lookup key.</param>
        /// <returns>
        /// The localized string, or a marker [[key]] if not found or on error.
        /// </returns>
        public static string GetString(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                return string.Empty;
            }

            if (_resourceManager == null || _currentCulture == null)
            {
                return $"[[{key}]]";
            }

            try
            {
                string? value = _resourceManager.GetString(key, _currentCulture);
                return string.IsNullOrWhiteSpace(value) ? $"[[{key}]]" : value;
            }
            catch (MissingManifestResourceException)
            {
                // Missing resource file or key
                return $"[[{key}]]";
            }
            catch (Exception ex)
            {
                // Unexpected error during lookup
                Debug.WriteLine($"Localization error for '{key}': {ex.Message}");
                return $"[[{key}]]";
            }
        }

        /// <summary>
        /// Initializes the localization system to the specified culture code.
        /// Resets the ResourceManager and applies the culture to the current thread.
        /// </summary>
        /// <param name="languageCode">
        /// Two-letter culture code (e.g. "en", "fr") or full code ("fr-FR").
        /// </param>
        public static void Initialize(string languageCode)
        {
            try
            {
                _currentCulture = new CultureInfo(languageCode);
            }
            catch (CultureNotFoundException)
            {
                // Fallbacks to invariant if the code is invalid
                _currentCulture = CultureInfo.InvariantCulture;
            }

            // Applies to current and default UI culture
            Thread.CurrentThread.CurrentUICulture = _currentCulture;
            CultureInfo.DefaultThreadCurrentUICulture = _currentCulture;

            // Points to the embedded Strings.resx in this assembly
            _resourceManager = new ResourceManager("chat_server.Resources.Strings",
                Assembly.GetExecutingAssembly());
        }
    }
}
