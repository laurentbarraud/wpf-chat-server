/// <file>LeftOffsetToMarginConverter.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 10th, 2026</date>

using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace ChatClient.Converters
{
    /// <summary>
    /// Converts a left-offset value (double) into a Margin, applying the offset
    /// to the left side while keeping the other sides unchanged.
    /// </summary>
    public class LeftOffsetToMarginConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double offset)
                return new Thickness(offset, 0, 0, 2);

            return new Thickness(0, 0, 0, 2);
        }

        /// <summary>
        /// Not supported — converting back from percentage to font size is not implemented.
        /// </summary>
        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => Binding.DoNothing;
    }
}

