/// <file>BoolToVisibilityConverter.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 15th, 2026</date>

using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace ChatClient.Converters
{
    /// <summary>
    /// Converts a boolean value into a Visibility value.
    /// True  -> Visibility.Visible
    /// False -> Visibility.Collapsed
    /// </summary>
    public class BoolToVisibilityConverter : IValueConverter
    {
        /// <summary>
        /// Converts a boolean value to a Visibility value.
        /// </summary>
        /// <param name="value">The boolean value to convert.</param>
        /// <returns>Visible if true, Collapsed if false.</returns>
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is bool isVisible && isVisible)
            {
                return Visibility.Visible;
            }

            return Visibility.Collapsed;
        }

        /// <summary>
        /// ConvertBack is not supported for this converter.
        /// </summary>
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("BoolToVisibilityConverter does not support ConvertBack.");
        }
    }
}
