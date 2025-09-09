using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides centralized logic for applying localized watermark brushes to TextBox controls.
    /// </summary>
    public static class WatermarksManager
    {
        /// <summary>
        /// Applies the appropriate watermark brush to supported TextBoxes based on current language and theme.
        /// </summary>
        /// <param name="targetWindow">The window containing the TextBoxes.</param>
        public static void RefreshWatermarks(Window targetWindow)
        {
            string appLanguageSaved = Properties.Settings.Default.AppLanguage;
            string appThemeSaved = Properties.Settings.Default.AppTheme;
            string suffix = appThemeSaved == "dark" ? "_dark" : "";

            ApplyBrushToTextBox(targetWindow, "txtUsername", $"txtUsername_background_{appLanguageSaved}{suffix}");
            ApplyBrushToTextBox(targetWindow, "txtIPAddress", $"txtIPAddress_background_{appLanguageSaved}{suffix}");
        }

        /// <summary>
        /// Applies a watermark brush to a TextBox if it's empty, otherwise clears the background.
        /// </summary>
        /// <param name="window">The window containing the TextBox.</param>
        /// <param name="textBoxName">The name of the TextBox control.</param>
        /// <param name="resourceKey">The key of the ImageBrush resource to apply.</param>
        private static void ApplyBrushToTextBox(Window window, string textBoxName, string resourceKey)
        {
            if (window.FindName(textBoxName) is not TextBox textBox)
                return;

            try
            {
                if (window.TryFindResource(resourceKey) is Brush brush)
                {
                    textBox.Background = string.IsNullOrWhiteSpace(textBox.Text) ? brush : null;
                }
            }
            catch (Exception ex)
            {
                // Optional: log or ignore silently to prevent crash
                Console.WriteLine($"Watermark resource '{resourceKey}' not found: {ex.Message}");
            }
        }

        /// <summary>
        /// Updates the background of a single TextBox when its content changes.
        /// Should be called from TextChanged event handlers.
        /// </summary>
        /// <param name="textBox">The TextBox being edited.</param>
        /// <param name="window">The window that owns the TextBox and its resources.</param>
        public static void UpdateWatermarkOnTextChanged(TextBox textBox, Window window)
        {
            string appLanguageSaved = Properties.Settings.Default.AppLanguage;
            string appThemeSaved = Properties.Settings.Default.AppTheme;
            string suffix = appThemeSaved == "dark" ? "_dark" : "";

            string fieldKey = null;

            if (textBox.Name == "txtUsername")
                fieldKey = "txtUsername";
            else if (textBox.Name == "txtIPAddress")
                fieldKey = "txtIPAddress";

            if (fieldKey == null)
                return;

            string resourceKey = $"{fieldKey}_background_{appLanguageSaved}{suffix}";

            try
            {
                if (window.TryFindResource(resourceKey) is Brush brush)
                {
                    textBox.Background = string.IsNullOrWhiteSpace(textBox.Text) ? brush : null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to update watermark for '{fieldKey}': {ex.Message}");
            }
        }
    }
}
