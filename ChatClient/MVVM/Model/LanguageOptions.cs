/// <file>LanguageOption.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 9th, 2026</date>

using System.ComponentModel;
using System.Globalization;

namespace ChatClient.MVVM.Model
{
    /// <summary>
    /// Represents one language choice with its ISO code and
    /// a localized display name according to the current UI culture.
    /// </summary>
    public class LanguageOptions : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary> 
        /// Returns the URI of the flag image corresponding to this 
        /// language code. 
        /// </summary>
        public string FlagPath
        {
            get
            {
                // Maps ISO code to lowercase file base name
                string languageName = LanguageCode switch
                {
                    "en" => "english",
                    "fr" => "french",
                    _ => LanguageCode.ToLowerInvariant()
                };

                // Builds the full resource path
                return $"/resources/{languageName}-flag.png";
            }
        }

        /// <summary> Stores the ISO language code. </summary>
        public string LanguageCode { get; }

        /// <summary> 
        /// Returns the culture’s native language name depending on the 
        /// current UI culture. 
        /// </summary>
        public string DisplayName =>  CultureInfo.GetCultureInfo(LanguageCode).DisplayName;

        /// <summary> Initializes the option with its ISO code. </summary>
        /// <param name="languageCode"></param>
        public LanguageOptions(string languageCode) => LanguageCode = languageCode;

        /// <summary> Notifies WPF that the DisplayName has changed after a culture update. </summary>
        public void NotifyCultureChanged()
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DisplayName)));
        }
    }
}
