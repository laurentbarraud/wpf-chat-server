/// <file>SlightLightenConverter.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 8th, 2026</date>

using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace ChatClient.Converters
{
    /// <summary>
    /// Slightly increases the brightness of a Color.
    /// Used to create a subtle vertical gradient on message bubbles.
    /// </summary>
    public class SlightLightenConverter : IValueConverter
    {
        /// <summary>
        /// Percentage of brightness to add.
        /// Default is +6%, which is visually subtle but effective.
        /// </summary>
        public double BoostFactor { get; set; } = 0.06;

        /// <summary> 
        /// Normalizes the RGB components of the input color to the [0–1] range, 
        /// applies a small brightness boost by pushing each component closer to 1.0, 
        /// then converts the result back into a Color. 
        /// This provides a simple and controlled way to lighten a color without altering its original hue.
        /// </summary>
        public object Convert(object inputValue, Type targetType, object parameter, CultureInfo culture)
        {
            // Ensures the input is a Color
            if (inputValue is not Color baseColor)
            {
                return inputValue;
            }

            // Converts each RGB component (0–255) into a normalized value between 0 and 1.
            // This makes it easier to apply a brightness adjustment.
            double normalizedRed = baseColor.R / 255.0;
            double normalizedGreen = baseColor.G / 255.0;
            double normalizedBlue = baseColor.B / 255.0;

            // Applies the brightness boost.
            // We gently push each component toward 1.0 (pure white),
            // which produces a subtle lightening effect without distorting the hue.
            normalizedRed = Math.Min(1.0, normalizedRed + BoostFactor);
            normalizedGreen = Math.Min(1.0, normalizedGreen + BoostFactor);
            normalizedBlue = Math.Min(1.0, normalizedBlue + BoostFactor);

            // Converts the normalized components back into byte values (0–255)
            // and reconstruct the final Color instance.
            return Color.FromRgb(
                (byte)(normalizedRed * 255),
                (byte)(normalizedGreen * 255),
                (byte)(normalizedBlue * 255)
            );
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
