/// <file>MonitorViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 13th, 2026</date>

using ChatClient.Helpers;
using ChatClient.MVVM.Model;
using ChatClient.MVVM.ViewModel;
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

        /// <summary> Returns a shortened excerpt of a public key for display purposes. </summary> 
        private string ExtractExcerpt(string publicKey) 
        { 
            if (string.IsNullOrWhiteSpace(publicKey))
            {
                return string.Empty; 
            }

            return publicKey.Length <= 20 ? publicKey : publicKey.Substring(0, 20) + "..."; 
        }

        /// <summary> Localized text displayed when a public key is invalid or missing. </summary> 
        public string InvalidOrMissingKeyText { get; private set; } = string.Empty;

        /// <summary> 
        /// Observable collection used as the DataGrid source. 
        /// Contains UI-ready entries with localized status text.
        /// </summary>
        public ObservableCollection<PublicKeyEntry> KnownPublicKeysView { get; }

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
        /// Rebuilds the DataGrid source from the internal KnownPublicKeys dictionary.
        /// Each entry is transformed into a UI-ready PublicKeyEntry with localized status text.
        /// </summary>
        public void RefreshFromDictionary(Dictionary<Guid, byte[]> knownKeys)
        {
            KnownPublicKeysView.Clear();

            foreach (var entry in knownKeys)
            {
                string username = _mainViewModel.ResolveUsername(entry.Key);

                // Converts the byte[] to a readable Base64 string
                string fullKey = entry.Value is { Length: > 0 }
                    ? Convert.ToBase64String(entry.Value)
                    : string.Empty;

                KnownPublicKeysView.Add(new PublicKeyEntry
                {
                    Username = username,
                    KeyExcerpt = ExtractExcerpt(fullKey),
                    StatusText = string.IsNullOrWhiteSpace(fullKey)
                        ? InvalidOrMissingKeyText
                        : ValidKeyText
                });
            }
        }
    }
}

