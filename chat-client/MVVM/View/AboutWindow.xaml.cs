/// <file>AboutWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 1st, 2026</date>

using chat_client.Helpers;
using System;
using System.Windows;
using System.Windows.Input;

namespace chat_client.MVVM.View
{
    public partial class AboutWindow : Window
    {
        public AboutWindow()
        {
            InitializeComponent();
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

        private void CmdSystemInfo_Click(object sender, RoutedEventArgs e)
        {
            /// <summary> 
            /// Launches Windows System Information (msinfo32).
            /// The UseShellExecute = true option ensures that the process is started 
            /// via the Windows shell, which is compatible with all versions.
            /// </summary>
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "msinfo32.exe",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(LocalizationManager.GetString("ErrorOpeningSystemInfo") + " " + ex.Message);
            }

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
