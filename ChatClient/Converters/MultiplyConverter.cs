/// <file>MultiplyConverter.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 18th, 2026</date>

using System;
using System.Globalization;
using System.Windows.Data;

namespace ChatClient.Converters
{
    /// <summary>
    /// Multiplies a numeric value by a given factor to compute proportional UI positions.
    /// It uses the container’s ActualWidth/ActualHeight and applies a ratio so the hotspot
    /// stays correctly aligned even when the image or window scales.
    /// </summary>
    public class MultiplyConverter : IValueConverter
    {
        public object Convert(object valueProvided, Type targetType, object parameterProvided, CultureInfo culture)
        {
            if (valueProvided is double value &&
                parameterProvided is string parameter &&
                double.TryParse(parameter, NumberStyles.Any, CultureInfo.InvariantCulture, out double factor))
            {
                return value * factor;
            }

            return 0;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}

