/// <file>LocalizationManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 22th, 2025</date>

using System.Globalization;
using System.Resources;

namespace chat_server.Helpers
{
    /// <summary>
    /// Manages localized strings for the console server.
    /// </summary>
    public static class LocalizationManager
    {
        private static ResourceManager __ResourceManager;
        private static CultureInfo _culture;

        public static void Initialize(string languageCode)
        {
            _culture = new CultureInfo(languageCode);
            __ResourceManager = new ResourceManager("chat_server.Resources.Strings", typeof(LocalizationManager).Assembly);
        }

        public static string GetString(string key)
        {
            return __ResourceManager.GetString(key, _culture);
        }
    }
}
