/// <file>EncryptionPipeline.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 22th, 2026</date>

using ChatClient.MVVM.Model;
using ChatClient.MVVM.ViewModel;
using ChatClient.Net;
using ChatClient.Properties;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel;

namespace ChatClient.Helpers
{
    /// <summary>
    /// EncryptionPipeline centralizes all encryption logic.
    /// • Start or stop the encryption pipeline safely.
    /// • Publish the local public key once per session.
    /// • Synchronize peer keys.
    /// • Update UI state with IsEncryptionReady.
    /// • Provide a single entry point for disabling encryption.
    /// 
    /// This class is called from MainViewModel and ClientConnection
    /// to keep UI and network code separate from encryption logic.
    /// </summary>
    public class EncryptionPipeline : INotifyPropertyChanged
    {
        // PRIVATE FIELDS

        /// <summary>
        /// Cancellation token source for the current pipeline run
        /// </summary>
        private CancellationTokenSource? _cts;

        /// <summary>
        /// Flag indicating if the pipeline is ready for encryption
        /// </summary>
        private bool _isEncryptionReady;

        /// <summary>
        /// Provides access to the active client connection for sending and receiving encryption data.
        /// </summary>
        private readonly ClientConnection _clientConn;

        /// <summary>
        /// Callback used to run actions on the UI thread, ensuring safe property updates.
        /// </summary>
        private readonly Action<Action> _uiDispatcherInvoke;

        /// <summary>
        /// Reference to the main view model, used to access user and peer information for encryption.
        /// </summary>
        private readonly MainViewModel _viewModel;

        // PUBLIC PROPERTIES

        /// <summary>
        /// Indicates whether the encryption pipeline is fully initialized
        /// and ready to encrypt/decrypt messages.
        /// </summary>
        public bool IsEncryptionReady
        {
            get => _isEncryptionReady;
            set
            {
                if (_isEncryptionReady != value)
                {
                    _isEncryptionReady = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsEncryptionReady)));
                }
            }
        }
 
        /// <summary>
        /// Unique source of truth for all known public keys, 
        /// exposed as a live collection of PublicKeyEntry.
        /// Directly bound to the monitor so that any change 
        /// in the encryption pipeline is reflected in the UI
        /// in real time.
        /// </summary>
        public ObservableCollection<PublicKeyEntry> KnownPublicKeys { get; }
            = new ObservableCollection<PublicKeyEntry>();

        /// <summary>
        /// Occurs when a property value changes.
        /// Used by WPF data binding to update the UI when
        /// properties such as IsEncryptionReady change.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Local user’s own RSA public key (DER-encoded).
        /// Must be initialized before handshake completion.
        /// </summary>
        public byte[] PublicKeyDer { get; set; }

        /// <summary>
        /// Creates a new EncryptionPipeline.
        /// Requires a MainViewModel, a ClientConnection for network operations,
        /// and one callback to run code on the UI thread.
        /// This keeps encryption logic separate while still updating the interface.
        /// </summary>
        /// <param name="viewModel">The active MainViewModel instance.</param>
        /// <param name="clientConn">The active client connection used for sending/receiving encryption data.</param>
        /// <param name="uiDispatcherInvoke">Callback to marshal actions onto the UI thread.</param>
        public EncryptionPipeline(MainViewModel viewModel, ClientConnection clientConn, Action<Action> uiDispatcherInvoke)
        {
            _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
            _clientConn = clientConn ?? throw new ArgumentNullException(nameof(clientConn));
            _uiDispatcherInvoke = uiDispatcherInvoke ?? throw new ArgumentNullException(nameof(uiDispatcherInvoke));
            
            /// <summary> Triggers static constructor if not already run </summary>
            _ = EncryptionHelper.PublicKeyDer;

            /// <summary> Initializes local public key material </summary>
            PublicKeyDer = EncryptionHelper.PublicKeyDer;
        }

        /// <summary>
        /// Generates a short, stable excerpt of a public key for display in the monitor.
        /// The method converts the DER-encoded key to Base64 and returns the first
        /// 20 characters followed by "....". If the input is null or empty, an empty
        /// string is returned. This ensures consistent formatting and avoids exposing
        /// the full key in the UI.
        /// </summary>

        private string ComputeExcerpt(byte[]? der)
        {
            if (der == null || der.Length == 0)
                return string.Empty;

            string base64 = Convert.ToBase64String(der);
            return base64.Length > 20 ? base64.Substring(0, 20) + "...." : base64;
        }

        /// <summary>
        /// Disables encryption in a safe, idempotent way.
        /// Cancels the active pipeline, clears key material, updates settings,
        /// resets internal flags, and notifies the UI.
        /// </summary>
        public void DisableEncryption()
        {
            // Avoids double-disable and unnecessary work
            if (!Settings.Default.UseEncryption)
            {
                return;
            }

            // Cancels any running encryption pipeline
            try
            {
                _cts?.Cancel();
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"DisableEncryption: error while cancelling CTS — {ex.Message}",
                    ClientLogLevel.Debug);
            }

            _cts?.Dispose();
            _cts = null;

            // Clears all known public keys for a clean state
            KnownPublicKeys.Clear();

            // Resets pipeline readiness flag
            IsEncryptionReady = false;

            // Resets UI bindings and encryption-related indicators
            _viewModel.ResetEncryptionPipelineAndUI();

            // Updates persisted setting
            Settings.Default.UseEncryption = false;
            Settings.Default.Save();
            
            ClientLogger.Log("Encryption disabled — pipeline cancelled, keys cleared, UI reset",
                ClientLogLevel.Info);
        }

        /// <summary>
        /// Evaluates whether encryption is ready by synchronizing the known public keys
        /// with the current roster and updating the UI-bound collection in-place.
        /// All modifications to KnownPublicKeys are dispatched to the UI thread.
        /// </summary>
        public bool EvaluateEncryptionState()
        {
            bool encryptionReady = false;

            // Encryption disabled or local user missing: nothing to evaluate.
            if (!Settings.Default.UseEncryption || _viewModel.LocalUser == null)
            {
                ClientLogger.Log("EvalEnc: encryption disabled or local user missing.", ClientLogLevel.Info);
                SetEncryptionReady(false);
                return false;
            }

            var encPipeline = _viewModel.EncryptionPipeline;
            if (encPipeline == null)
            {
                ClientLogger.Log("EvalEnc: pipeline is null.", ClientLogLevel.Warn);
                SetEncryptionReady(false);
                return false;
            }

            // Local UID for convenience.
            Guid localUid = _viewModel.LocalUser.UID;

            // Build a list of all users except the local one.
            var peers = _viewModel.Users
                .Where(u => u.UID != localUid)
                .ToList();

            // --- UI-thread update of KnownPublicKeys ---
            _uiDispatcherInvoke(() =>
            {
                foreach (var user in _viewModel.Users)
                {
                    // Compute excerpt from the pipeline
                    string excerpt = ComputeExcerpt(user.PublicKeyDer);

                    // Find existing entry.
                    var entry = encPipeline.KnownPublicKeys.FirstOrDefault(e => e.UID == user.UID);

                    if (entry == null)
                    {
                        // Create a fully initialized entry.
                        entry = new PublicKeyEntry
                        {
                            UID = user.UID,
                            Username = user.Username,
                            KeyExcerpt = excerpt,
                            IsLocal = (user.UID == localUid),
                            StatusText = excerpt.Length > 0 ? "Valid" : "Missing"
                        };

                        encPipeline.KnownPublicKeys.Add(entry);
                    }
                    else
                    {
                        // Update in-place.
                        entry.Username = user.Username;
                        entry.KeyExcerpt = excerpt;
                        entry.IsLocal = (user.UID == localUid);
                        entry.StatusText = entry.IsValid ? "Valid" : "Missing";
                    }
                }

                // Remove entries for users no longer in the roster.
                var stale = encPipeline.KnownPublicKeys
                    .Where(e => !_viewModel.Users.Any(u => u.UID == e.UID))
                    .ToList();

                foreach (var s in stale)
                    encPipeline.KnownPublicKeys.Remove(s);
            });

            // --- Evaluate readiness ---
            if (peers.Count == 0)
            {
                // Solo mode: only the local key matters.
                encryptionReady = encPipeline.KnownPublicKeys.Any(e => e.IsLocal && e.IsValid);
                ClientLogger.Log($"EvalEnc: solo mode → Ready={encryptionReady}", ClientLogLevel.Info);
            }
            else
            {
                // Multi-user mode: all peers must have valid keys.
                bool allValid = peers.All(p =>
                {
                    var entry = encPipeline.KnownPublicKeys.FirstOrDefault(e => e.UID == p.UID);
                    return entry != null && entry.IsValid;
                });

                encryptionReady = allValid;
                ClientLogger.Log($"EvalEnc: multi-user → Ready={encryptionReady}", ClientLogLevel.Info);
            }

            // Update UI flag.
            _uiDispatcherInvoke(() => SetEncryptionReady(encryptionReady));

            return encryptionReady;
        }


        /// <summary>
        /// Initializes the encryption pipeline: restores local key material if needed,
        /// injects the local public key into the key registry, synchronizes peer keys,
        /// and computes the final encryption readiness state.
        /// </summary>
        public async Task<bool> InitializeEncryptionAsync(CancellationToken cancellationToken)
        {
            if ((_viewModel == null) || (_viewModel.LocalUser == null))
            {
                ClientLogger.Log("Init encryption aborted — ViewModel or LocalUser missing.", ClientLogLevel.Error);
                return false;
            }

            // Ensures local key material exists (fallback to EncryptionHelper if ViewModel is empty)
            if (((_viewModel.LocalUser.PublicKeyDer == null) || (_viewModel.LocalUser.PublicKeyDer.Length == 0)) &&
                (EncryptionHelper.PublicKeyDer != null) && (EncryptionHelper.PublicKeyDer.Length > 0))
            {
                _viewModel.LocalUser.PublicKeyDer = EncryptionHelper.PublicKeyDer;
                ClientLogger.Log("Local public key materialized from EncryptionHelper.", ClientLogLevel.Debug);
            }

            if (((_viewModel.LocalUser.PrivateKeyDer == null) || (_viewModel.LocalUser.PrivateKeyDer.Length == 0)) &&
                (EncryptionHelper.PrivateKeyDer != null) && (EncryptionHelper.PrivateKeyDer.Length > 0))
            {
                _viewModel.LocalUser.PrivateKeyDer = EncryptionHelper.PrivateKeyDer;
                ClientLogger.Log("Local private key materialized from EncryptionHelper.", ClientLogLevel.Debug);
            }

            // Injects local public key into KnownPublicKeys
            if ((_viewModel.LocalUser.PublicKeyDer != null) && (_viewModel.LocalUser.PublicKeyDer.Length > 0))
            {
                Guid localUserUid = _viewModel.LocalUser.UID;
                byte[] localPublicKeyDer = _viewModel.LocalUser.PublicKeyDer;

                var matchingEntry = KnownPublicKeys
                    .FirstOrDefault(e => e.UID == localUserUid);

                string computedExcerpt = Convert.ToBase64String(localPublicKeyDer);
                if (computedExcerpt.Length > 20)
                {
                    computedExcerpt = computedExcerpt.Substring(0, 20) + "....";
                }

                if (matchingEntry != null)
                {
                    matchingEntry.KeyExcerpt = computedExcerpt;
                    matchingEntry.Username = _viewModel.LocalUser.Username;
                    matchingEntry.IsLocal = true;
                }
                else
                {
                    KnownPublicKeys.Add(
                        new PublicKeyEntry
                        {
                            UID = localUserUid,
                            Username = _viewModel.LocalUser.Username,
                            KeyExcerpt = computedExcerpt,
                            IsLocal = true
                        }
                    );

                    ClientLogger.Log("Local public key injected into KnownPublicKeys.", ClientLogLevel.Debug);
                }
            }

            // Syncs peer keys
            bool peerKeySyncSucceeded = await SyncKeysAsync(cancellationToken).ConfigureAwait(false);

            // Computes final encryption readiness
            bool encryptionReady = (peerKeySyncSucceeded && EvaluateEncryptionState());

            // Pushes state to UI
            _uiDispatcherInvoke(() =>
            {
                if (_viewModel != null)
                {
                    SetEncryptionReady(encryptionReady);
                }
            });

            ClientLogger.Log($"Init encryption completed — Ready={encryptionReady}", ClientLogLevel.Info);

            return encryptionReady;
        }

        /// <summary>
        /// Sets the encryption ready flag and notifies listeners if changed.
        /// </summary>
        public void SetEncryptionReady(bool isEncReady)
        {
            if (IsEncryptionReady == isEncReady)
            {
                return;
            }

            IsEncryptionReady = isEncReady;
        }

        /// <summary>
        /// Synchronizes public keys with all connected peers by publishing
        /// the local key, requesting missing peer keys, 
        /// and waiting until all keys are available or a timeout occurs.
        /// </summary>
        public async Task<bool> SyncKeysAsync(CancellationToken cancellationToken)
        {
            // Validates that encryption prerequisites are present before proceeding.
            if (_viewModel?.LocalUser?.PublicKeyDer == null || _viewModel.LocalUser.PublicKeyDer.Length == 0)
            {
                _uiDispatcherInvoke(() => IsEncryptionReady = false);
                return false;
            }

            // Marks encryption as not ready (syncing state is active).
            _uiDispatcherInvoke(() => IsEncryptionReady = false);

            try
            {
                // Collects peer IDs excluding the local user.
                var peerIds = _viewModel.Users
                    .Where(u => u.UID != _viewModel.LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                // Solo mode: only valid if the list of connected users is stable.
                if (peerIds.Count == 0 && _viewModel.IsFirstRosterSnapshot == false)
                {
                    _uiDispatcherInvoke(() => IsEncryptionReady = true);
                    ClientLogger.Log("SyncKeysAsync: solo mode — no peers present, encryption ready.", ClientLogLevel.Info);
                    return true;
                }

                // Publishes the local public key to the server.
                var localKey = _viewModel.LocalUser.PublicKeyDer;

                if (localKey == null || localKey.Length == 0)
                {
                    ClientLogger.Log("SyncKeysAsync aborted — local public key not initialized.", ClientLogLevel.Error);
                    _uiDispatcherInvoke(() => IsEncryptionReady = false);
                    return false;
                }

                // Pushes local public key to server
                await _clientConn.SendPublicKeyToServerAsync(_viewModel.LocalUser.UID, localKey, _viewModel.LocalUser.UID,
                    cancellationToken).ConfigureAwait(false);

                // Identifies peers whose public keys are missing.
                List<Guid> missingKeys = peerIds
                    .Where(uid =>
                    {
                        var missingEntry = KnownPublicKeys.FirstOrDefault(e => e.UID == uid);
                        return missingEntry == null || !missingEntry.IsValid;
                    })
                    .ToList();

                ClientLogger.Log($"SyncKeysAsync: peers={peerIds.Count}, missing={missingKeys.Count}", ClientLogLevel.Debug);

                // Requests missing keys sequentially from peers.
                foreach (var uid in missingKeys)
                {
                    await _clientConn.SendRequestToPeerForPublicKeyAsync(uid, cancellationToken);
                }

                // Defines timeout and start time for key synchronization.
                var timeout = TimeSpan.FromSeconds(5);
                var startTime = DateTime.UtcNow;

                // Loops until all peer keys are received or timeout occurs.
                while (true)
                {
                    var stillMissing = peerIds
                        .Where(uid =>
                        {
                            var missingEntry = KnownPublicKeys.FirstOrDefault(e => e.UID == uid);
                            return missingEntry == null || !missingEntry.IsValid;
                        })
                        .ToList();

                    if (stillMissing.Count == 0)
                    {
                        _uiDispatcherInvoke(() => IsEncryptionReady = true);
                        break;
                    }

                    if (DateTime.UtcNow - startTime > timeout)
                    {
                        _uiDispatcherInvoke(() => IsEncryptionReady = false);
                        ClientLogger.Log("SyncKeysAsync: timeout waiting for peer keys", ClientLogLevel.Warn);
                        break;
                    }

                    await Task.Delay(200, cancellationToken);
                }

                return IsEncryptionReady;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"SyncKeysAsync failed: {ex.Message}", ClientLogLevel.Error);
                return false;
            }
        }

    }
}

