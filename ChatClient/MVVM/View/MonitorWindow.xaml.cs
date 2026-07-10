/// <file>MonitrWindow.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>July 10th, 2026</date>

using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace ChatClient.MVVM.View
{
    /// <summary>
    /// Public keys monitor, window bound to the global view model.
    /// Allows users to display live-refreshing information about public keys
    /// and to request each missing public key from peers.
    /// </summary>
    public partial class MonitorWindow : Window
    {
        private bool _columnsBuilt = false;

        /// <summary>
        /// Initializes the monitor window, assigns the global view model as DataContext,
        /// anchors the window to the owner's bottom‑right corner,
        /// and listens for language changes to refresh localized UI.
        /// </summary>
        public MonitorWindow()
        {
            InitializeComponent();

            App.ViewModel.LanguageChanged += (_, _) =>
            {
                if (_columnsBuilt)
                {
                    ApplyLocalizedHeaders();
                }
            };

            PublicKeysDataGrid.Loaded += PublicKeysDataGrid_Loaded;
        }

        /// <summary>
        /// Applies localized header texts to the DataGrid columns based on the current language settings.
        /// </summary>
        private void ApplyLocalizedHeaders()
        {
            if (PublicKeysDataGrid.Columns.Count < 4)
            {
                return;
            }

            PublicKeysDataGrid.Columns[0].Header = App.ViewModel.UsernameHeader;
            PublicKeysDataGrid.Columns[1].Header = App.ViewModel.KeyExcerptHeader;
            PublicKeysDataGrid.Columns[2].Header = App.ViewModel.StatusHeader;
            PublicKeysDataGrid.Columns[3].Header = App.ViewModel.ActionHeader;
        }

        /// <summary>
        /// Builds the DataGrid columns programmatically.  
        /// This avoids XAML binding issues and ensures the column structure  
        /// is created once during the DataGrid's Loaded event.
        /// </summary>
        private void BuildColumns()
        {
            // username column
            var colUsername = new DataGridTextColumn
            {
                Binding = new Binding("Username"),
                Width = new DataGridLength(4, DataGridLengthUnitType.Star)
            };

            // key excerpt column (template defined in xaml)
            var colExcerpt = new DataGridTemplateColumn
            {
                Width = new DataGridLength(2.5, DataGridLengthUnitType.Star),
                CellTemplate = (DataTemplate)FindResource("KeyExcerptTemplate")
            };

            // status column (template defined in xaml)
            var colStatus = new DataGridTemplateColumn
            {
                Width = new DataGridLength(2, DataGridLengthUnitType.Star),
                CellTemplate = (DataTemplate)FindResource("StatusTemplate")
            };

            // action button column (template defined in xaml)
            var colAction = new DataGridTemplateColumn
            {
                Width = new DataGridLength(1.5, DataGridLengthUnitType.Star),
                CellTemplate = (DataTemplate)FindResource("ActionTemplate")
            };

            PublicKeysDataGrid.Columns.Add(colUsername);
            PublicKeysDataGrid.Columns.Add(colExcerpt);
            PublicKeysDataGrid.Columns.Add(colStatus);
            PublicKeysDataGrid.Columns.Add(colAction);
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

            else if (Application.Current.MainWindow is MainWindowLegacy mainWindowLegacy)
            {
                mainWindowLegacy.HideMonitorButton();
            }
        #endif
        }

        private void PublicKeysDataGrid_Loaded(object sender, RoutedEventArgs e) 
        {
            if (!_columnsBuilt)
            {
                BuildColumns(); 
                _columnsBuilt = true; 
            }
            
            ApplyLocalizedHeaders();
        }
    }
}
