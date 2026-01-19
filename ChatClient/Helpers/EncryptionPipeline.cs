/// <file>EncryptionPipeline.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 18th, 2026</date>

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
        /// Unique source of truth for all known public keys.
        /// Directly bound to the monitor, ensuring real-time
        /// UI updates without manual synchronization and
        /// eliminating desynchronization risks.
        /// </summary>
        public ObservableCollection<KeyValuePair<Guid, byte[]>> KnownPublicKeys { get; }
            = new ObservableCollection<KeyValuePair<Guid, byte[]>>();

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
        /// Evaluates whether encryption is ready by checking local and peer public keys, 
        /// snchronizing missing keys, and updating UI state. 
        /// </summary>
        public bool EvaluateEncryptionState()
        {
            bool encryptionReady = false;

            // Ensures that encryption is enabled and local user exists.
            if (!Settings.Default.UseEncryption || (_viewModel.LocalUser == null))
            {
                ClientLogger.Log("EvalEnc: encryption disabled or local user missing.", ClientLogLevel.Info);
            }

            // Solo mode: only the local key is required.
            else if (_viewModel.Users.Count <= 1)
            {
                byte[] localPublicKey = _viewModel.LocalUser.PublicKeyDer;
                byte[] helperPublicKey = EncryptionHelper.PublicKeyDer;

                if ((localPublicKey?.Length > 0) || (helperPublicKey?.Length > 0))
                {
                    ClientLogger.Log("EvalEnc: solo mode detected, encryption ready.", ClientLogLevel.Info);
                    encryptionReady = true;
                }
                else
                {
                    ClientLogger.Log("EvalEnc: solo mode detected, but no local key defined.", ClientLogLevel.Warn);
                }
            }

            // Multi-user mode: all peers must have valid public keys.
            else
            {
                var encryptionPipeline = _viewModel!.EncryptionPipeline;
                if (encryptionPipeline == null)
                {
                    ClientLogger.Log("EvalEnc: pipeline is null.", ClientLogLevel.Warn);
                }
                else
                {
                    // Collects all peer UIDs except the local user.
                    List<Guid> peerUids = _viewModel.Users
                        .Where(u => u.UID != _viewModel.LocalUser.UID)
                        .Select(u => u.UID)
                        .ToList();

                    // Synchronizes roster keys into KnownPublicKeys.
                    foreach (var user in _viewModel.Users)
                    {
                        if (user.UID == _viewModel.LocalUser.UID)
                        {
                            continue;
                        }

                        if ((user.PublicKeyDer != null) && (user.PublicKeyDer.Length > 0))
                        {
                            var existingPublicKey = encryptionPipeline.KnownPublicKeys
                                .FirstOrDefault(e => e.Key == user.UID);

                            if (existingPublicKey.Key == user.UID)
                            {
                                int indexExistingKey = encryptionPipeline.KnownPublicKeys.IndexOf(existingPublicKey);
                                
                                if (indexExistingKey >= 0)
                                {
                                    encryptionPipeline.KnownPublicKeys[indexExistingKey] =
                                        new KeyValuePair<Guid, byte[]>(user.UID, user.PublicKeyDer);
                                }
                            }
                            else
                            {
                                encryptionPipeline.KnownPublicKeys.Add(new KeyValuePair<Guid, byte[]>(user.UID, user.PublicKeyDer));
                            }
                        }
                    }

                    // Detects missing or empty peer keys.
                    List<Guid> missingKeys = new List<Guid>();

                    foreach (Guid peerUid in peerUids)
                    {
                        var entry = encryptionPipeline.KnownPublicKeys
                            .FirstOrDefault(e => e.Key == peerUid);

                        byte[] peerKey = entry.Value;

                        if ((peerKey == null) || (peerKey.Length == 0))
                        {
                            missingKeys.Add(peerUid);
                        }
                    }

                    if (missingKeys.Count == 0)
                    {
                        ClientLogger.Log("EvalEnc: all peer keys present -> ready.", ClientLogLevel.Info);
                        encryptionReady = true;
                    }
                    else
                    {
                        ClientLogger.Log($"EvalEnc: missing peer keys -> {string.Join(", ", missingKeys)}",
                            ClientLogLevel.Debug);
                    }
                }
            }

            // Updates UI flags.
            _uiDispatcherInvoke(() =>
            {
                SetEncryptionReady(encryptionReady);
            });

            ClientLogger.Log($"EvalEnc: final Ready={encryptionReady}", ClientLogLevel.Debug);
            return encryptionReady;
        }

        /// <summary>
        /// Initializes the encryption pipeline: materializes local key material,
        /// injects the local public key, syncs peer keys, and updates encryption state.
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
                // Restores public key from helper
                _viewModel.LocalUser.PublicKeyDer = EncryptionHelper.PublicKeyDer;
                ClientLogger.Log("Local public key materialized from EncryptionHelper.", ClientLogLevel.Debug);
            }

            if (((_viewModel.LocalUser.PrivateKeyDer == null) || (_viewModel.LocalUser.PrivateKeyDer.Length == 0)) &&
                (EncryptionHelper.PrivateKeyDer != null) && (EncryptionHelper.PrivateKeyDer.Length > 0))
            {
                // Restores private key from helper
                _viewModel.LocalUser.PrivateKeyDer = EncryptionHelper.PrivateKeyDer;
                ClientLogger.Log("Local private key materialized from EncryptionHelper.", ClientLogLevel.Debug);
            }

            // Injects local public key
            if ((_viewModel.LocalUser.PublicKeyDer != null) && (_viewModel.LocalUser.PublicKeyDer.Length > 0))
            {
                Guid localUserUid = _viewModel.LocalUser.UID;
                byte[] localPublicKeyDer = _viewModel.LocalUser.PublicKeyDer;

                bool localKeyAlreadyPresent = KnownPublicKeys.Any(entry => entry.Key == localUserUid);

                if (!localKeyAlreadyPresent)
                {
                    KnownPublicKeys.Add(new KeyValuePair<Guid, byte[]>(localUserUid, localPublicKeyDer));
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
        /// Registers the local user's public key received during the handshake.
        /// Stores the key in LocalUser and injects it into KnownPublicKeys.
        /// This method does not evaluate or modify encryption readiness.
        /// </summary>
        public void RegisterLocalHandshakeKey(Guid uid, byte[] publicKeyProvided)
        {
            if ((publicKeyProvided == null) || (publicKeyProvided.Length == 0))
            {
                throw new InvalidOperationException("Public key not initialized");
            }

            // Stores the handshake key in the local user model.
            _viewModel.LocalUser.PublicKeyDer = publicKeyProvided;

            // Injects or updates the key in the pipeline.
            var encryptionPipeline = _viewModel!.EncryptionPipeline;
            if (encryptionPipeline == null)
            {
                ClientLogger.Log("RegisterLocalHandshakeKey: pipeline is null.", ClientLogLevel.Warn);
                return;
            }

            // Looks for an existing entry.
            var existingEntry = encryptionPipeline.KnownPublicKeys
                .FirstOrDefault(e => e.Key == uid);

            if (existingEntry.Key == uid)
            {
                // Updates existing entry.
                int index = encryptionPipeline.KnownPublicKeys.IndexOf(existingEntry);
                if (index >= 0)
                {
                    encryptionPipeline.KnownPublicKeys[index] =
                        new KeyValuePair<Guid, byte[]>(uid, publicKeyProvided);
                }
            }
            else
            {
                // Inserts new entry.
                encryptionPipeline.KnownPublicKeys.Add(new KeyValuePair<Guid, byte[]>(uid, publicKeyProvided));
            }

            ClientLogger.Log($"MarkReadyForSession — UID={uid}, PublicKeyLen={publicKeyProvided.Length}",
                ClientLogLevel.Debug);
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
        /// Synchronizes public keys with all connected peers by publishing the local key,
        /// requesting missing peer keys, and waiting until all keys are available or a timeout occurs.
        /// Handles solo mode and updates encryption readiness accordingly.
        /// </summary>
        public async Task<bool> SyncKeysAsync(CancellationToken cancellationToken)
        {
            // Validates that encryption prerequisites are present before proceeding.
            // Falls back to false if local key material is missing.
            if (_viewModel?.LocalUser?.PublicKeyDer == null || _viewModel.LocalUser.PublicKeyDer.Length == 0)
            {
                _uiDispatcherInvoke(() =>
                {
                    IsEncryptionReady = false;
                });
                return false;
            }

            // Marks syncing state as active and encryption as not ready.
            _uiDispatcherInvoke(() =>
            {
                IsEncryptionReady = false;
            });

            try
            {
                // Collects peer IDs excluding the local user.
                var peerIds = _viewModel.Users
                    .Where(u => u.UID != _viewModel.LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                // Solo mode: only valid if the roster is truly stable,
                // that is no peers and initial roster already processed.
                // Prevents premature "ready" state for encryption when other clients haven't connected yet.
                if (peerIds.Count == 0 && _viewModel.IsFirstRosterSnapshot == false)
                {
                    _uiDispatcherInvoke(() =>
                    {
                        IsEncryptionReady = true;
                    });
                    ClientLogger.Log("SyncKeysAsync: solo mode — no peers present, encryption ready.", ClientLogLevel.Info);
                    return true;
                }

                // Publishes the local public key to the server for distribution in multi-client mode.
                // Ensures that the payload is never null.
                var localKey = _viewModel.LocalUser.PublicKeyDer;

                if (localKey == null || localKey.Length == 0)
                {
                    ClientLogger.Log("SyncKeysAsync aborted — local public key not initialized.", ClientLogLevel.Error);
                    _uiDispatcherInvoke(() =>
                    {
                        IsEncryptionReady = false;
                    });
                    return false;
                }

                await _clientConn.SendPublicKeyToServerAsync(_viewModel.LocalUser.UID, localKey, _viewModel.LocalUser.UID,
                    cancellationToken).ConfigureAwait(false);

                // Identifies peers whose public keys are missing.
                List<Guid> missingKeys;
                {
                    missingKeys = peerIds
                        .Where(uid =>
                        {
                            var entry = KnownPublicKeys.FirstOrDefault(e => e.Key == uid);
                            return entry.Value == null || entry.Value.Length == 0;
                        })
                        .ToList();
                }

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
                            var entry = KnownPublicKeys.FirstOrDefault(e => e.Key == uid);
                            return entry.Value == null || entry.Value.Length == 0;
                        })
                        .ToList();

                    if (stillMissing.Count == 0)
                    {
                        _uiDispatcherInvoke(() =>
                        {
                            IsEncryptionReady = true;
                        });
                        break;
                    }

                    if (DateTime.UtcNow - startTime > timeout)
                    {
                        _uiDispatcherInvoke(() =>
                        {
                            IsEncryptionReady = false;
                        });
                        
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

