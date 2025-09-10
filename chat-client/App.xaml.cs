/// <file>App.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 10th, 2025</date>

using System.Configuration;
using System.Data;
using System.Windows;
using chat_client.Helpers;
using chat_client.Properties;

namespace chat_client
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Get saved theme preference from settings
            bool useDarkTheme = Settings.Default.AppTheme == "Dark";

            // Apply the selected theme with fade animation
            ThemeManager.ApplyTheme(useDarkTheme);
        }
    }

}
