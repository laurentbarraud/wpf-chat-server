/// <file>MonitorViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 13th, 2026</date>

using ChatClient.Helpers;
using ChatClient.MVVM.Model;
using ChatClient.MVVM.ViewModel;
using ChatClient.Properties;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;

namespace ChatClient.MVVM.ViewModel
{
    /// <summary>
    /// ViewModel for the public keys monitor window.
    /// Provides localized licence information and CLI link text.
    /// Implements INotifyPropertyChanged for UI binding updates.
    /// </summary>
    public class MonitorViewModel : INotifyPropertyChanged
    {
        // PRIVATE FIELDS
        private readonly MainViewModel _mainViewModel;

        /// <summary> Backing fields for localized strings </summary>
        private string _monitorWindowTitle = string.Empty;

        // PUBLIC PROPERTIES

        /// <summary>
        /// Returns a short, human‑readable excerpt of a DER‑encoded public key.
        /// Produces a hexadecimal preview of the first bytes, followed by "...".
        /// </summary>
        private string ExtractExcerpt(byte[] publicKeyDer)
        {
            if (publicKeyDer == null || publicKeyDer.Length == 0)
                return string.Empty;

            // Take the first 8 bytes (or fewer if the key is extremely short)
            int excerptLength = Math.Min(8, publicKeyDer.Length);

            // Convert to hex without dashes (e.g. "A1B2C3D4...")
            string hex = BitConverter.ToString(publicKeyDer, 0, excerptLength).Replace("-", "");

            return hex + "...";
        }

        /// <summary> Localized text displayed when a public key is invalid or missing. </summary> 
        public string InvalidOrMissingKeyText { get; private set; } = string.Empty;

        /// <summary>
        /// True when the DataGrid should be visible.
        /// </summary> 
        public bool IsGridVisible => MaskMessage == null;
        
        /// <summary> 
        /// True when a mask message should be displayed instead of the grid.
        /// </summary>
        public bool IsMaskVisible => MaskMessage != null;

        /// <summary> 
        /// Observable collection used as the DataGrid source. 
        /// Contains UI-ready entries with localized status text.
        /// </summary>
        public ObservableCollection<PublicKeyEntry> KnownPublicKeysView { get; }

        /// <summary>
        /// Gets the current mask message to display over the monitor grid.
        /// Returns null when no mask should be shown.
        /// </summary>
        public string? MaskMessage
        {
            get
            {
                if (!Settings.Default.UseEncryption)
                {
                    return LocalizationManager.GetString("EnableEncryptionToSeePublicKeysState");
                }

                if (!_mainViewModel.IsConnected)
                {
                    return LocalizationManager.GetString("NotConnected");
                }

                return null;
            }
        }

        /// <summary> Localized text for the monitor window title. </summary>
        public string MonitorWindowTitle
        {
            get => _monitorWindowTitle;
            set
            {
                _monitorWindowTitle = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary> Localized text displayed when a public key is valid. </summary>
        public string ValidKeyText { get; private set; } = string.Empty;

        /// <summary>
        /// Initializes the ViewModel with localized strings.
        /// </summary>
        public MonitorViewModel(MainViewModel mainViewModel)
        {
            _mainViewModel = mainViewModel ?? throw new ArgumentNullException(nameof(mainViewModel));

            KnownPublicKeysView = new ObservableCollection<PublicKeyEntry>();
            MonitorWindowTitle = LocalizationManager.GetString("MonitorWindowTitle");
            ValidKeyText = LocalizationManager.GetString("ValidKey"); 
            InvalidOrMissingKeyText = LocalizationManager.GetString("InvalidOrMissingKey");

            // Subscribes to state changes so the mask reacts automatically.
            _mainViewModel.PropertyChanged += MainViewModelOnPropertyChanged;
            _mainViewModel.LanguageChanged += OnLanguageChanged;
            Settings.Default.PropertyChanged += OnSettingsChanged;

            // Adds the local client's own public key as the first entry
            KnownPublicKeysView.Add(new PublicKeyEntry
            {
                Username = _mainViewModel.Username,
                KeyExcerpt = ExtractExcerpt(_mainViewModel.LocalUser.PublicKeyDer),
                StatusText = ValidKeyText,
                IsLocal = true
            });
        }

        /// <summary>
        /// Propagates relevant state changes from the MainViewModel
        /// so that the mask and grid visibility stay in sync.
        /// Here as soon as IsConnected changes in MainViewModel, 
        /// WPF knows that MaskMessage, IsMaskVisible and IsGridVisible have changed.
        /// </summary>
        private void MainViewModelOnPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(MainViewModel.IsConnected))
            {
                OnPropertyChanged(nameof(MaskMessage));
                OnPropertyChanged(nameof(IsMaskVisible));
                OnPropertyChanged(nameof(IsGridVisible));
            }
        }

        /// <summary>
        /// Refreshes mask-related properties when the application language changes.
        /// </summary>
        private void OnLanguageChanged(object? sender, EventArgs e)
        {
            OnPropertyChanged(nameof(MaskMessage));
            OnPropertyChanged(nameof(IsMaskVisible));
            OnPropertyChanged(nameof(IsGridVisible));
        }

        /// <summary>
        /// Helper method that use CallerMemberName to avoid hardcoding property names.
        /// Notifies the UI that a property value has changed.
        /// </summary>
        /// <param name="propertyName">The name of the changed property.</param>
        protected void OnPropertyChanged([CallerMemberName] string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        /// <summary>
        /// Refreshes mask-related properties when application settings change,
        /// such as enabling or disabling encryption.
        /// </summary>
        private void OnSettingsChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(Settings.Default.UseEncryption))
            {
                OnPropertyChanged(nameof(MaskMessage));
                OnPropertyChanged(nameof(IsMaskVisible));
                OnPropertyChanged(nameof(IsGridVisible));
            }
        }

        /// <summary>
        /// Rebuilds the DataGrid source from the internal KnownPublicKeys dictionary.
        /// Each entry is transformed into a UI-ready PublicKeyEntry with localized status text.
        /// </summary>
        public void RefreshFromDictionary(Dictionary<Guid, byte[]> knownKeys)
        {
            KnownPublicKeysView.Clear();

            foreach (var entry in knownKeys)
            {
                string username = _mainViewModel.ResolveUsername(entry.Key);
                byte[] keyBytes = entry.Value;

                KnownPublicKeysView.Add(new PublicKeyEntry
                {
                    Username = username,
                    KeyExcerpt = ExtractExcerpt(keyBytes),
                    StatusText = keyBytes is { Length: > 0 }
                        ? ValidKeyText
                        : InvalidOrMissingKeyText
                });
            }
        }
    }
}

