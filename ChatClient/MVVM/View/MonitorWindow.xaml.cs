/// <file>MonitrWindow.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 25th, 2026</date>

using ChatClient.MVVM.ViewModel;             // For MonitorViewModel
using ChatClient.Net;
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

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
        /// Initializes the monitor window, assigns the MainViewModel as its DataContext,
        /// ensures access to EncryptionPipeline and KnownPublicKeys from XAML bindings,
        /// and subscribes to language change notifications to refresh localized UI elements.
        /// </summary>
        public MonitorWindow(MainViewModel mainViewModel)
        {
            InitializeComponent();
            DataContext = mainViewModel!;

            // Subscribes to language change event
            mainViewModel!.LanguageChanged += MainViewModel_LanguageChanged;
        }

        private void CmdValidate_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        /// <summary>
        /// Refreshes DataGrid column headers when the application language changes.
        /// </summary>
        private void MainViewModel_LanguageChanged(object? sender, EventArgs e)
        {
            foreach (var column in PublicKeysDataGrid.Columns)
            {
                var binding = BindingOperations.GetBindingExpression(column, DataGridColumn.HeaderProperty);
                binding?.UpdateTarget();
            }
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
