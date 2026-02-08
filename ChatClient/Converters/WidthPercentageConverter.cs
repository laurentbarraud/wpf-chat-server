/// <file>WidthPercentageConverter.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 8th, 2026</date>

using System;
using System.Globalization;
using System.Windows.Data;

namespace ChatClient.MVVM.Converters
{
    public class WidthPercentageConverter : IValueConverter
    {
        public double Factor { get; set; } = 0.7;

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double width)
            {
                return width * Factor;
            }

            return 300; // fallback
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}
