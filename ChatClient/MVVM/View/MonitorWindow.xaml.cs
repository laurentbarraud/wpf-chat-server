/// <file>MonitrWindow.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 22th, 2026</date>

using ChatClient.MVVM.ViewModel;             // For MonitorViewModel
using ChatClient.Net;
using System;
using System.Windows;

namespace ChatClient.MVVM.View
{
    /// <summary>
    /// Public keys monitor, window bound to the main ViewModel.
    /// Allows users to display live-refreshing information about public keys
    /// and to request each missing public key from peers.
    /// </summary>
    public partial class MonitorWindow : Window
    {
        /// <summary>
        /// Initializes the monitor window and assigns the MainViewModel as DataContext.
        /// This ensures that EncryptionPipeline and KnownPublicKeys are directly accessible
        /// from the XAML bindings.
        /// </summary>
        public MonitorWindow(MainViewModel mainViewModel)
        {
            InitializeComponent();
            DataContext = mainViewModel;
        }

        private void CmdValidate_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void MonitorWindow1_Closed(object sender, EventArgs e)
        {
        #if !DEBUG
            if (Application.Current.MainWindow is MainWindow mainWindow)
            {
                mainWindow.HideMonitorButton();
            }
        #endif
        }
    }
}
