/// <file>AboutWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 22th, 2025</date>

using chat_client.Helpers;
using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Animation;

namespace chat_client.View
{
    public partial class AboutWindow : Window
    {
        // Prevents re-triggering while mouse stays over
        private bool VersionTextAnimated = false;
 
        public AboutWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            this.Title = LocalizationManager.GetString("About");
            LicenceInfoText.Text = LocalizationManager.GetFormattedString("LicenceInfo");
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
        /// On hover over the entire trimmed text (version + date): shows and slides the name once,
        /// stops with 5px spacing, illuminates.
        /// </summary>
        private void LicenceTrimmedBlock_MouseEnter(object sender, MouseEventArgs e)
        {
            if (!VersionTextAnimated)
            {
                VersionTextAnimated = true;
                Storyboard open = (Storyboard)FindResource("storyBoardLicenceTrimmed_Open");
                open.Begin(this);
            }
        }

        /// <summary>
        /// On mouse leave: waits 2s, then fades the name out slowly and resets the flag.
        /// </summary>
        private void LicenceTrimmedBlock_MouseLeave(object sender, MouseEventArgs e)
        {
            Storyboard close = (Storyboard)FindResource("storyBoardLicenceTrimmed_Close");
            close.Begin(this);
            VersionTextAnimated = false;
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
