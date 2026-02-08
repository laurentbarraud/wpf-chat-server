/// <file>BoolToVisibilityConverter.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 8th, 2026</date>

using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace ChatClient.Converters
{
    /// <summary>
    /// Converts a boolean value into a Visibility value.
    /// True becomes Visible
    /// False becomes Collapsed
    /// Supports inversion via invParameter.
    /// </summary>
    public class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object invParameter, CultureInfo culture)
        {
            // Checks inversion request
            bool invertRequested = invParameter?.ToString()?.Equals("Invert", StringComparison.OrdinalIgnoreCase) == true;

            // Validates input type
            if (value is bool sourceBool)
            {
                // Applies optional inversion
                bool effectiveBool = invertRequested ? !sourceBool : sourceBool;

                // Maps to visibility
                return effectiveBool ? Visibility.Visible : Visibility.Collapsed;
            }

            // Fallback for non-boolean values
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("BoolToVisibilityConverter does not support ConvertBack.");
        }
    }

}

