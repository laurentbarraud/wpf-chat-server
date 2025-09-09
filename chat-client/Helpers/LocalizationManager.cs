using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Resources;
using System.Text;
using System.Threading.Tasks;

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
    }
}
