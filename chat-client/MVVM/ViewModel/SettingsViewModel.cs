/// <file>SettingsViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 21th, 2025</date>


// The System.ComponentModel namespace enables WPF to track property changes
// via INotifyPropertyChanged,
// while System.Runtime.CompilerServices allows automatic property name injection
// using [CallerMemberName] for clean and reactive UI updates.

using chat_client.Helpers;
using chat_client.MVVM.Model;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;

namespace chat_client.MVVM.ViewModel
{
    /// <summary>
    /// ViewModel for SettingsWindow.
    /// Holds application settings as properties.
    /// Setting this object as the DataContext makes all properties
    /// accessible from XAML via {Binding …}.
    /// </summary>
    public class SettingsViewModel : INotifyPropertyChanged
    {
        /// <summary>
        /// Collection of languages for the ComboBox (ISO code + localized name).
        /// </summary>
        public ObservableCollection<LanguageOptions> SupportedLanguages { get; }
            = new ObservableCollection<LanguageOptions>
            {
                new LanguageOptions("en"),
                new LanguageOptions("fr")
            };

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Application UI language code.
        /// Persists user choice, reloads resources, and updates UI labels.
        /// </summary>
        public string AppLanguage
        {
            get => _appLanguage;
            set
            {
                if (_appLanguage == value) return;
                _appLanguage = value;
                OnPropertyChanged();  // Notify UI of AppLanguage change

                // Persist the new language choice
                Properties.Settings.Default.AppLanguage = value;
                Properties.Settings.Default.Save();

                // Reload localization resources and refresh all UI labels
                LocalizationManager.Initialize(value);
                LocalizationManager.UpdateLocalizedUI();

                // Refresh ComboBox items so each DisplayName re‐localizes
                OnPropertyChanged(nameof(SupportedLanguages));
            }
        }

        /// <summary>
        /// Custom TCP port number.
        /// </summary>
        public int CustomPortNumber
        {
            get => _customPortNumber;
            set
            {
                if (_customPortNumber == value) return;
                _customPortNumber = value;
                OnPropertyChanged();                                     // Notifies UI of port change
                Properties.Settings.Default.CustomPortNumber = value;           // Persists new port
                Properties.Settings.Default.Save();
            }
        }

        /// <summary>
        /// Minimizes the app to system tray when true.
        /// </summary>
        public bool ReduceToTray
        {
            get => _reduceToTray;
            set
            {
                if (_reduceToTray == value) return;
                _reduceToTray = value;
                OnPropertyChanged();                                     // Notifies UI of toggle change
                Properties.Settings.Default.ReduceToTray = value;         // Persists toggle
                Properties.Settings.Default.Save();
            }
        }

        /// <summary>
        /// Enables or disables the custom port section.
        /// </summary>
        public bool UseCustomPort
        {
            get => _useCustomPort;
            set
            {
                if (_useCustomPort == value) return;
                _useCustomPort = value;
                /// <summary>Notifies UI of toggle change</summary>
                OnPropertyChanged();                                    
                Properties.Settings.Default.UseCustomPort = value;       
                Properties.Settings.Default.Save();
            }
        }

        /// <summary>
        /// Proxy property that exposes the encryption toggle state
        /// from the MainViewModel. This allows the SettingsWindow
        /// to bind directly to UseEncryption while delegating the
        /// actual logic and state management to the MainViewModel.
        /// </summary>
        public bool UseEncryption
        {
            get => _mainViewModel.UseEncryption;
            set
            {
                if (_mainViewModel.UseEncryption != value)
                {
                    _mainViewModel.UseEncryption = value;
                    OnPropertyChanged(nameof(UseEncryption));
                }
            }
        }

        // Backing private fields
        private string _appLanguage = Properties.Settings.Default.AppLanguage;
        private int _customPortNumber = Properties.Settings.Default.CustomPortNumber;
        
        // Reference to the MainViewModel instance
        private readonly MainViewModel _mainViewModel;
        
        private bool _reduceToTray = Properties.Settings.Default.ReduceToTray;
        private bool _useCustomPort = Properties.Settings.Default.UseCustomPort;

        /// <summary>
        /// Initializes a new instance of the SettingsViewModel class.
        /// Requires a reference to the MainViewModel so that global states
        /// such as encryption can be proxied and controlled from the SettingsWindow.
        /// </summary>
        public SettingsViewModel(MainViewModel mainViewModel)
        {
            _mainViewModel = mainViewModel;
        }

        // In a WinForms app you'd typically update controls directly (e.g. myTextBox.Text = value).
        // In WPF, you expose properties on a ViewModel and rely on data binding to push changes to the UI.
        // Implementing INotifyPropertyChanged and calling OnPropertyChanged tells the WPF binding engine
        // “hey, this property’s value just changed—refresh any bound controls.”  
        // The [CallerMemberName] attribute means you don’t have to hard-code the property name string;
        // the compiler automatically fills in the name of the property or method that called OnPropertyChanged.
        protected void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}

