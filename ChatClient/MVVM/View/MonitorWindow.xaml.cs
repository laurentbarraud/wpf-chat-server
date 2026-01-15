/// <file>MonitrWindow.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 15th, 2026</date>

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
        private readonly MonitorViewModel _monitorViewModel;
        private readonly MainViewModel _mainViewModel = new MainViewModel();

        public MainViewModel MainViewModel => _mainViewModel;

        /// <summary> 
        /// Initializes the window and assigns its ViewModel. 
        /// Retrieves the MainViewModel from the application's main window 
        /// and injects it into the MonitorViewModel before setting the DataContext.
        /// </summary>
        public MonitorWindow()
        {
            InitializeComponent();

            // Retrieves the MainViewModel of the application
            var mainViewModel = Application.Current.MainWindow.DataContext as MainViewModel 
                ?? throw new InvalidOperationException("MainViewModel not found.");

            // Injects the real MainViewModel into the MonitorViewModel
            _monitorViewModel = new MonitorViewModel(mainViewModel!);
            DataContext = _monitorViewModel;
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

        private void MonitorWindow1_Loaded(object sender, RoutedEventArgs e)
        {
            if (DataContext is MonitorViewModel monitorViewModel) 
            {
                monitorViewModel.RefreshFromDictionary(MainViewModel.ClientConn.GetKnownPublicKeys()); 
            }
        }
    }
}
