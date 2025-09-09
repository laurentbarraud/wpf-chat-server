using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;

namespace chat_client.Helpers
{
    /// <summary>
    /// Manages dynamic watermark image selection and visibility based on language, theme, and field state.
    /// </summary>
    public static class WatermarksManager
    {
        /// <summary>
        /// Returns the correct watermark image path based on field name, language, and theme.
        /// </summary>
        public static string GetWatermarkPath(string fieldName)
        {
            string appLanguageSet = Properties.Settings.Default.AppLanguage; // "en" or "fr"
            string themeSet = Properties.Settings.Default.AppTheme; // "light" or "dark"

            string suffix = themeSet == "dark" ? "_dark" : "";
            string fileName = $"{fieldName}_background_{appLanguageSet}{suffix}";

            return $"/Resources/{fileName}.png";
        }

        /// <summary>
        /// Applies the correct watermark image to the given Image control.
        /// </summary>
        public static void ApplyWatermark(Image imageControl, string fieldName)
        {
            string path = GetWatermarkPath(fieldName);
            imageControl.Source = new BitmapImage(new Uri(path, UriKind.Relative));
        }

        /// <summary>
        /// Updates watermark visibility based on the content of the associated TextBox.
        /// </summary>
        public static void UpdateVisibility(Image imageControl, TextBox textBox)
        {
            imageControl.Visibility = string.IsNullOrWhiteSpace(textBox.Text)
                ? Visibility.Visible : Visibility.Collapsed;
        }
    }
}
