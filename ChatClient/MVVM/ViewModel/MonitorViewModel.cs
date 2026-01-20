/// <file>MonitorViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 20th, 2026</date>

using ChatClient.Helpers;
using ChatClient.MVVM.Model;
using ChatClient.MVVM.ViewModel;
using ChatClient.Properties;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;

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
        /// Exposes the live collection of known public keys maintained by the encryption pipeline.
        /// Returns null until the connection and pipeline are fully initialized.
        /// </summary>
        public ObservableCollection<KeyValuePair<Guid, byte[]>>? KnownPublicKeys
        {
            get => _mainViewModel?.ClientConn?.EncryptionPipeline?.KnownPublicKeys;
        }

        /// <summary> 
        /// Exposes the MainViewModel instance used by this monitor,
        /// allowing access to the application's shared state and connection.
        /// </summary>
        public MainViewModel MainViewModel => _mainViewModel;

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

        /// <summary>
        /// Command exposed to the View
        /// </summary>
        public ICommand RequestMissingPublicKeyCommand { get; } = null!;


        /// <summary> Localized text displayed when a public key is valid. </summary>
        public string ValidKeyText { get; private set; } = string.Empty;

        /// <summary>
        /// Initializes the ViewModel with localized strings.
        /// </summary>
        public MonitorViewModel(MainViewModel mainViewModel)
        {
            _mainViewModel = mainViewModel ?? throw new ArgumentNullException(nameof(mainViewModel));

            MonitorWindowTitle = LocalizationManager.GetString("MonitorWindowTitle");
            ValidKeyText = LocalizationManager.GetString("ValidKey");
            InvalidOrMissingKeyText = LocalizationManager.GetString("InvalidOrMissingKey");

            // Subscribes to state changes so the mask reacts automatically.
            _mainViewModel.PropertyChanged += MainViewModelOnPropertyChanged;
            _mainViewModel.LanguageChanged += OnLanguageChanged;
            Settings.Default.PropertyChanged += OnSettingsChanged;

            // Command to request a missing public key from a peer
            RequestMissingPublicKeyCommand = new RelayCommand<KeyValuePair<Guid, byte[]>>(
                async entry => await RequestMissingPublicKeyAsync(entry)
            );
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
            MonitorWindowTitle = LocalizationManager.GetString("MonitorWindowTitle"); 
            ValidKeyText = LocalizationManager.GetString("ValidKey"); 
            InvalidOrMissingKeyText = LocalizationManager.GetString("InvalidOrMissingKey");
  
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
        /// Sends a targeted request to a specific peer asking for its public key.
        /// The request is forwarded to the network layer.
        /// </summary>
        private async Task RequestMissingPublicKeyAsync(KeyValuePair<Guid, byte[]> entry)
        {
            var uid = entry.Key;

            if (uid == _mainViewModel.LocalUser.UID)
            {
                return;
            }

            try
            {
                await _mainViewModel.ClientConn
                    .SendRequestToPeerForPublicKeyAsync(uid, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"RequestMissingKeyAsync failed for UID {uid}: {ex.Message}", ClientLogLevel.Error);
            }
        }

    }
}

