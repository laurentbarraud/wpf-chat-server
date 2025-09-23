using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Navigation;
using chat_client.Helpers;



namespace chat_client.View
{
    public partial class AboutWindow : Window
    {
        public AboutWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Handles click on the CLI arguments hyperlink and displays the help MessageBox.
        /// </summary>
        private void CliHyperlink_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
        {
            ShowCliHelp();
            e.Handled = true; // Stop automatic navigation: essential if the link
                              // must act as a button without opening a browser.
        }

        /// <summary>
        /// Closes the About window when the OK button is clicked.
        /// Used in CLI mode to terminate the application after displaying version info.
        /// </summary>
        private void cmdOk_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        /// <summary>
        /// Displays a localized MessageBox listing all supported command-line arguments.
        /// Retrieves the CLI help text and title from resource files using LocalizationManager.
        /// Converts escaped newline characters into actual line breaks for proper formatting.
        /// </summary>
        private void ShowCliHelp()
        {
            string raw = LocalizationManager.GetString("CliHelpText") ?? "[[CliHelpText]]";
            string title = LocalizationManager.GetString("CliHelpTitle") ?? "[[CliHelpTitle]]";

            string formatted = raw.Replace("\\n", "\n").Replace("\\t", "\t");

            MessageBox.Show(formatted, title, MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
