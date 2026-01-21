/// <file>MonitorViewModel.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 21th, 2026</date>

using ChatClient.Helpers;
using ChatClient.MVVM.Model;
using ChatClient.MVVM.ViewModel;
using ChatClient.Properties;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
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

        /// <summary>
        /// Handle to know which instance of the ObservableCollection the ViewModel 
        /// is currently subscribed to.
        /// </summary>
        private ObservableCollection<PublicKeyEntry>? _subscribedKnownPublicKeys;

        // PUBLIC PROPERTIES

        /// <summary> Localized text displayed when a public key is invalid or missing. </summary> 
        public string InvalidOrMissingKeyText { get; private set; } = string.Empty;

        /// <summary> True when the DataGrid should be visible. </summary> 
        public bool IsGridVisible => MaskMessage == null;
        
        /// <summary> True when a mask message should be displayed instead of the grid. </summary>
        public bool IsMaskVisible => MaskMessage != null;

        /// <summary>
        /// Calculated property, whose value is obtained via a getter, 
        /// not stored in a field, that returns a direct reference to
        /// the collection of public key entries exposed by the encryption pipeline. 
        /// Returns null until the connection and encryption pipeline are fully initialized.
        /// </summary>
        public ObservableCollection<PublicKeyEntry>? KnownPublicKeys
            => _mainViewModel?.ClientConn?.EncryptionPipeline?.KnownPublicKeys;

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
        /// <summary>
        /// Standard INotifyPropertyChanged event used to notify the UI when a property value changes.
        /// Raised by calling OnPropertyChanged, allowing WPF bindings to refresh automatically.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;


        /// <summary> 
        /// Command bound to the action button in the monitor grid. 
        /// Sends a targeted request for the missing public key of the selected user, 
        /// using the UID as the command parameter. 
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
            RequestMissingPublicKeyCommand = new RelayCommand<Guid>(
                async uid => await RequestMissingPublicKeyAsync(uid)
            );

        }

        /// <summary>
        /// Attaches the ViewModel to the current KnownPublicKeys collection exposed by the pipeline.
        /// Ensures that the monitor listens to collection changes and detaches cleanly when
        /// the underlying collection instance is replaced (e.g. reconnection or new pipeline).
        /// </summary>
        private void AttachToKnownPublicKeys()
        {
            // Detaches from the previous collection instance, if any.
            if (_subscribedKnownPublicKeys != null)
                _subscribedKnownPublicKeys.CollectionChanged -= KnownPublicKeys_CollectionChanged;

            // Attaches to the current collection instance exposed by the pipeline.
            _subscribedKnownPublicKeys = KnownPublicKeys;
            if (_subscribedKnownPublicKeys != null)
                _subscribedKnownPublicKeys.CollectionChanged += KnownPublicKeys_CollectionChanged;

            // Notifies the UI that the ItemsSource may have changed (helps initial binding and reconnection).
            OnPropertyChanged(nameof(KnownPublicKeys));
        }

        /// <summary>
        /// Reacts to changes in the KnownPublicKeys collection.
        /// The DataGrid refreshes automatically when the collection changes, 
        /// but this handler also keeps the mask and grid visibility in sync
        /// with the current state.
        /// </summary>
        private void KnownPublicKeys_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        { 
            // The DataGrid will update automatically when the collection changes. 
            // But we also want to refresh mask visibility if needed.
            OnPropertyChanged(nameof(IsMaskVisible)); 
            OnPropertyChanged(nameof(IsGridVisible)); 
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

            // If MainViewModel can replace ClientConn or the EncryptionPipeline,
            // re-attach to KnownPublicKeys so the monitor always follows the current collection instance.
            if (e.PropertyName == "ClientConn" || e.PropertyName == "EncryptionPipeline")
            {
                AttachToKnownPublicKeys();
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
        /// The UID is provided directly by the monitor and forwarded to the network layer.
        /// Does nothing if the UID refers to the local user.
        /// </summary>
        private async Task RequestMissingPublicKeyAsync(Guid targetUid)
        {
            // Ignores requests targeting the local user's own UID.
            if (targetUid == _mainViewModel.LocalUser.UID)
                return;

            try
            {
                await _mainViewModel.ClientConn
                    .SendRequestToPeerForPublicKeyAsync(targetUid, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"RequestMissingPublicKeyAsync failed for UID {targetUid}: {ex.Message}",
                    ClientLogLevel.Error);
            }
        }
    }
}

