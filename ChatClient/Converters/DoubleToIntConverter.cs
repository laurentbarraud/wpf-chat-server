/// <file>DoubleToIntConverter.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 17th, 2026</date>

using System;
using System.Globalization;
using System.Windows.Data;

namespace ChatClient.Converters
{
    /// <summary>
    /// Converts between double and int values for Slider bindings.
    /// Ensures compatibility when a Slider (double) is bound to an int property.
    /// </summary>
    public class DoubleToIntConverter : IValueConverter
    {
        /// <summary>
        /// Converts a double value from the source to an int for the target property.
        /// </summary>
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double d)
                return System.Convert.ToInt32(d);
            return 0;
        }

        /// <summary>
        /// Converts an int value from the target back to a double for the Slider control.
        /// </summary>
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int i)
                return (double)i;
            return 0.0;
        }
    }
}
