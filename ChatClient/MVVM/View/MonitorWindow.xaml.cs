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
        /// Initializes the monitor window, assigns the MainViewModel as DataContext,
        /// anchors the window to the owner's bottom‑right corner,
        /// and listens for language changes to refresh localized UI.
        /// </summary>
        public MonitorWindow(MainViewModel mainViewModel)
        {
            InitializeComponent();
            DataContext = mainViewModel!;

            Loaded += (_, __) => PositionRelativeToOwnerBottomRight();
            Owner.LocationChanged += (_, __) => PositionRelativeToOwnerBottomRight();
            Owner.SizeChanged += (_, __) => PositionRelativeToOwnerBottomRight();

            mainViewModel.LanguageChanged += MainViewModel_LanguageChanged;
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

        /// <summary> 
        /// Positions the monitor window anchored to the bottom‑right corner of its owner.
        /// Uses the owner's current bounds to compute a stable offset, ensuring consistent
        /// placement even when the main window is resized or moved. 
        /// </summary> 
        public void PositionRelativeToOwnerBottomRight()
        {
            if (Owner == null)
            {
                return;
            }

            const double margin = 12;
            Left = Owner.Left + Owner.Width - Width - margin;
            Top = Owner.Top + Owner.Height - Height - margin;
        }
    }
}
