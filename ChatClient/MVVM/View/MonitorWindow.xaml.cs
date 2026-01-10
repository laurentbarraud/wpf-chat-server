/// <file>MonitorWindow.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 11th, 2026</date>

using System;
using ChatClient.MVVM.ViewModel;             // For MonitorViewModel
using System.ComponentModel;                 // For PropertyChangedEventArgs
using System.Windows;

namespace ChatClient.MVVM.View
{
    /// <summary>
    /// Public keys monitor, window bound to the main ViewModel.
    /// Allows users to display live-refreshing information about public keys
    /// and to request each missing public key from peers.
    /// </summary>
    public partial class MonitorWindow
    {
        private readonly MonitorViewModel _monitorViewModel;

        public MonitorWindow(MonitorViewModel monitorViewModel)
        {
            InitializeComponent();

            _monitorViewModel = monitorViewModel;
            DataContext = _monitorViewModel;

            // Listens to ViewModel property changes (language, tray behavior, etc.)
            _monitorViewModel.PropertyChanged += MonitorViewModel_PropertyChanged;
        }

        /// <summary>
        /// Handles property change notifications from MonitorViewModel.
        /// </summary>
        private void MonitorViewModel_PropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            
        }

        private void CmdValidate_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
