/// <file>AboutWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 30th, 2025</date>

using System;
using System.Windows;
using System.Windows.Input;
using chat_client.Helpers;

namespace chat_client.View
{
    public partial class AboutWindow : Window
    {
        public AboutWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            this.Title = LocalizationManager.GetString("About");
            LicenceFinalText.Text = LocalizationManager.GetFormattedString("LicenceFinal");
            LicenceInfo1Text.Text = LocalizationManager.GetFormattedString("LicenceInfo1");
            LicenceInfo2Text.Text = LocalizationManager.GetFormattedString("LicenceInfo2");
            LicenceInfoResourcesText.Text = LocalizationManager.GetFormattedString("LicenceInfoResources");
            CliTextBlock.Text = LocalizationManager.GetFormattedString("CommandLineArguments");
        }

        /// <summary>
        /// Handles click on the CLI arguments textblock and displays the help MessageBox.
        /// </summary>
        private void CliTextBlock_MouseDown(object sender, MouseButtonEventArgs e)
        {
            ShowCommandLineArgumentsHelp();
        }

        /// <summary>
        /// Closes the About window when the OK button is clicked.
        /// Used in CLI mode to terminate the application after displaying version info.
        /// </summary>
        private void CmdOk_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        /// <summary>
        /// Shows a localized MessageBox listing all supported CLI arguments.
        /// If this window was never shown (IsVisible==false), the app closes.
        /// Otherwise, the help box is just closed.
        /// </summary>
        public void ShowCommandLineArgumentsHelp()
        {
            // Retrieves raw help text and title from resources
            string rawCliOptionsHelpText = LocalizationManager.GetString("CliOptionsHelpText")
                             ?? "[[CliOptionsHelpText]]";
            string titleCliOptions = LocalizationManager.GetString("CliOptionsHelpTitle")
                             ?? "[[CliOptionsHelpTitle]]";

            // Converts escaped sequences to real line breaks and tabs
            string formattedCliOptionsHelpText = rawCliOptionsHelpText
                .Replace("\\n", "\n")
                .Replace("\\t", "\t");

            // Shows the styled MessageBox
            MessageBox.Show(
                formattedCliOptionsHelpText,
                titleCliOptions,
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            // If the AboutWindow was never shown, then exits the application
            if (!this.IsVisible)
                Application.Current.Shutdown();
        }
    }
}
