/// <file>LocalizeExtension.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 27th, 2025</date>

using System;
using System.Windows.Markup;
using chat_client.Helpers;

namespace chat_client.Helpers
{
    /// <summary>
    /// Retrieves a localized string by resource key for use in XAML.
    /// </summary>
    [MarkupExtensionReturnType(typeof(string))]
    public class LocalizeExtension : MarkupExtension
    {
        /// <summary>
        /// The resource key to look up in the LocalizationManager.
        /// Always non-null; defaulted to empty.
        /// </summary>
        public string Key { get; set; } = string.Empty;

        /// <summary>
        /// Initializes a new instance with an empty Key.
        /// </summary>
        public LocalizeExtension()
        {
            // Key is already non-null because of the initializer above.
        }

        /// <summary>
        /// Initializes a new instance with the specified resource key.
        /// </summary>
        public LocalizeExtension(string key)
        {
            Key = key ?? string.Empty;
        }

        /// <summary>
        /// Returns the localized string for the given Key,
        /// or a fallback marker if the key is missing.
        /// </summary>
        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            // Fetch via LocalizationManager; never returns null
            return LocalizationManager.GetString(Key);
        }
    }
}


