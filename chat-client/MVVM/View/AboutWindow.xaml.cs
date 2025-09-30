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
            ShowCliHelp();
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
        /// Displays a localized MessageBox listing all supported command-line arguments.
        /// Retrieves the CLI help text and title from resource files using LocalizationManager.
        /// Converts escaped newline characters into actual line breaks for proper formatting.
        /// </summary>
        private static void ShowCliHelp()
        {
            string raw = LocalizationManager.GetString("CliHelpText") ?? "[[CliHelpText]]";
            string title = LocalizationManager.GetString("CliHelpTitle") ?? "[[CliHelpTitle]]";

            string formatted = raw.Replace("\\n", "\n").Replace("\\t", "\t");

            MessageBox.Show(formatted, title, MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
