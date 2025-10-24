/// <file>LanguageOption.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 25th, 2025</date>

using System.Globalization;

namespace chat_client.MVVM.Model
{
    /// <summary>
    /// Represents one language choice with its ISO code and
    /// a localized display name according to the current UI culture.
    /// </summary>
    public class LanguageOptions
    {
        /// <summary>
        /// Returns the URI of the flag image corresponding to this language code.
        /// </summary>
        public string FlagPath
        {
            get
            {
                // Maps ISO code to lowercase file base name
                string fileBase = LanguageCode switch
                {
                    "en" => "english",
                    "fr" => "french",
                    _ => LanguageCode.ToLowerInvariant()
                };

                // Builds the full resource path
                return $"/resources/{fileBase}-flag.png";
            }
        }

        /// <summary>
        /// Stores the ISO code ("en", "fr", etc.)
        /// </summary>
        public string LanguageCode { get; }

        /// <summary>
        /// Returns the culture’s native language name ("English"/"Français" or "anglais"/"français")
        /// </summary>
        public string DisplayName =>
            CultureInfo.GetCultureInfo(LanguageCode)
                       .DisplayName;

        /// <summary>
        /// Initializes the option with its ISO code
        /// </summary>
        /// <param name="languageCode"></param>
        public LanguageOptions(string languageCode) =>
            LanguageCode = languageCode;
    }
}
