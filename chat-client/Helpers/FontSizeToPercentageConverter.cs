/// <file>FontSizeToPercentageConverter.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 11th, 2025</date>

using System;
using System.Globalization;
using System.Windows.Data;

namespace chat_client.Helpers
{
    /// <summary>
    /// Converts a font size value (12–20) into a readable percentage string.
    /// </summary>
    public class FontSizeToPercentageConverter : IValueConverter
    {
        /// <summary>
        /// Converts the numeric font size into a percentage relative to 14 = 100%.
        /// </summary>
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            // Ensures the value is an integer
            int valueInt = (int)value;

            // Base reference: 14 = 100%
            double percentReturned = (valueInt / 14.0) * 100.0;

            // Formats as "80%", "100%", "150%", etc.
            return $"{percentReturned:0}%";
        }

        /// <summary>
        /// Not supported — converting back from percentage to font size is not implemented.
        /// </summary>
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}

