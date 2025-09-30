/// <file>SettingsViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 30th, 2025</date>


// The System.ComponentModel namespace enables WPF to track property changes
// via INotifyPropertyChanged,
// while System.Runtime.CompilerServices allows automatic property name injection
// using [CallerMemberName] for clean and reactive UI updates.

using chat_client.Helpers;
using System.ComponentModel;
using System.Runtime.CompilerServices;

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
        public event PropertyChangedEventHandler? PropertyChanged;
       
        // Backing fields
        private int _customPortNumber;
        private bool _useCustomPort;
        private bool _reduceToTray;
        private bool _useEncryption;
        private string _appLanguage;


        /// <summary>
        /// Initializes all properties from saved settings.
        /// </summary>
        public SettingsViewModel()
        {
            _customPortNumber = Properties.Settings.Default.CustomPortNumber;
            _useCustomPort = Properties.Settings.Default.UseCustomPort;
            _reduceToTray = Properties.Settings.Default.ReduceToTray;
            _useEncryption = Properties.Settings.Default.UseEncryption;
            _appLanguage = Properties.Settings.Default.AppLanguage;
        }
        
        /// <summary>
        /// Application UI language code.
        /// </summary>
        public string AppLanguage
        {
            get => _appLanguage;
            set
            {
                if (_appLanguage == value) return;
                _appLanguage = value;
                OnPropertyChanged();                                     // Notifies UI of language change
                Properties.Settings.Default.AppLanguage = value;          // Persists language
                Properties.Settings.Default.Save();
                LocalizationManager.Initialize(value);                    // Reloads language resources
                LocalizationManager.UpdateLocalizedUI();                  // Refreshes all labels
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
        protected void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
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
                OnPropertyChanged();                                     // Notifies UI of toggle change
                Properties.Settings.Default.UseCustomPort = value;        // Persists toggle
                Properties.Settings.Default.Save();
            }
        }

        /// <summary>
        /// Enables or disables encryption pipeline.
        /// </summary>
        public bool UseEncryption
        {
            get => _useEncryption;
            set
            {
                if (_useEncryption == value) return;
                _useEncryption = value;
                OnPropertyChanged();                                     // Notifies UI of toggle change
                Properties.Settings.Default.UseEncryption = value;        // Persists toggle
                Properties.Settings.Default.Save();
            }
        }

    }
}

