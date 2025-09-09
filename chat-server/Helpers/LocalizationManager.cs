/// <file>LocalizationManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 9th, 2025</date>

using System.Globalization;
using System.Resources;

namespace ChatServer.Helpers
{
    /// <summary>
    /// Manages localized strings for the console server.
    /// </summary>
    public static class LocalizationManager
    {
        private static ResourceManager _resourceManager;
        private static CultureInfo _culture;

        public static void Initialize(string languageCode)
        {
            _culture = new CultureInfo(languageCode);
            _resourceManager = new ResourceManager("ChatServer.Resources.Strings", typeof(LocalizationManager).Assembly);
        }

        public static string GetString(string key)
        {
            return _resourceManager.GetString(key, _culture);
        }
    }
}
