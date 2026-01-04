/// <file>EncryptionPipeline.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 4th, 2026</date>

using chat_client.Net;
using chat_client.MVVM.ViewModel;
using chat_client.Properties;
using System;
using System.ComponentModel;

namespace chat_client.Helpers
{
    /// <summary>
    /// EncryptionPipeline centralizes all encryption logic.
    /// • Start or stop the encryption pipeline safely.
    /// • Publish the local public key once per session.
    /// • Synchronize peer keys.
    /// • Update UI state (IsSyncingKeys, IsEncryptionReady).
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
        /// Flag indicating if the pipeline is currently syncing keys
        /// </summary>
        private bool _isSyncingKeys;

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
        /// Indicates whether the pipeline is currently synchronizing
        /// public/private keys with peers or the server.
        /// </summary>
        public bool IsSyncingKeys
        {
            get => _isSyncingKeys;
            set
            {
                if (_isSyncingKeys != value)
                {
                    _isSyncingKeys = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSyncingKeys)));
                }
            }
        }

        /// <summary>
        /// Known public keys of peers (UID → DER bytes).
        /// Empty arrays are ignored and do not affect readiness.
        /// </summary>
        public Dictionary<Guid, byte[]> KnownPublicKeys { get; } = new();

        /// <summary>
        /// Occurs when a property value changes.
        /// Used by WPF data binding to update the UI when
        /// properties such as IsEncryptionReady or IsSyncingKeys change.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Local user’s own RSA public key (DER-encoded).
        /// Must be initialized before handshake completion.
        /// </summary>
        public byte[] PublicKeyDer { get; set; }

        /// <summary>
        /// Raised whenever IsEncryptionReady or IsSyncingKeys changes.
        /// </summary>
        public event EventHandler? StateChanged;

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
        /// Cancels the pipeline, clears key material, updates settings,
        /// resets flags, and notifies the UI.
        /// </summary>
        public void DisableEncryption()
        {
            // Avoids double-disable and duplicate logs
            if (!Settings.Default.UseEncryption)
            {
                return;
            }

            try
            {
                _cts?.Cancel();
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"DisableEncryption: CTS cancel error — {ex.Message}", ClientLogLevel.Debug);
            }

            _cts?.Dispose();
            _cts = null;

            KnownPublicKeys.Clear();

            // Resets all encryption-related flags and updates the UI bindings
            _viewModel.ResetEncryptionPipelineAndUI();

            Settings.Default.UseEncryption = false;

            try
            {
                Settings.Default.Save();
            }
            catch { }

            ClientLogger.Log("Encryption disabled via EncryptionPipeline.DisableEncryption().", ClientLogLevel.Info);
        }

        public bool EvaluateEncryptionState()
        {
            // Default: not ready
            bool ready = false;

            // Encryption disabled or local user not ready: bails out
            if (!Settings.Default.UseEncryption || _viewModel.LocalUser == null)
            {
                ClientLogger.Log("EvalEnc: encryption disabled or local user missing.", ClientLogLevel.Info);
            }

            // Solo mode: we just need our own key
            else if (_viewModel.Users.Count <= 1)
            {
                var localKey = _viewModel.LocalUser.PublicKeyDer;
                var helperKey = EncryptionHelper.PublicKeyDer;

                if (localKey?.Length > 0 || helperKey?.Length > 0)
                {
                    ClientLogger.Log("EvalEnc: solo mode → ready.", ClientLogLevel.Info);
                    ready = true;
                }
                else
                {
                    ClientLogger.Log("EvalEnc: solo mode but no local key.", ClientLogLevel.Warn);
                }
            }
            // Multi-user mode: all peers must have valid keys
            else
            {
                // Collects all peer UIDs except ourselves
                var peerUids = _viewModel.Users
                    .Where(u => u.UID != _viewModel.LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                List<Guid> missingKeys;

                lock (KnownPublicKeys)
                {
                    // Missing = peers not present OR peers with empty keys
                    missingKeys = peerUids
                        .Where(uid => !KnownPublicKeys.ContainsKey(uid) ||
                                      KnownPublicKeys[uid] == null ||
                                      KnownPublicKeys[uid].Length == 0)
                        .ToList();
                }

                if (missingKeys.Count == 0)
                {
                    ClientLogger.Log("EvalEnc: all peer keys present → ready.", ClientLogLevel.Info);
                    ready = true;
                }
                else
                {
                    ClientLogger.Log($"EvalEnc: missing peer keys → {string.Join(", ", missingKeys)}", ClientLogLevel.Debug);
                }
            }

            // Updates UI flags on dispatcher
            _uiDispatcherInvoke(() =>
            {
                SetEncryptionReady(ready);
                SetSyncing(!ready);
            });

            ClientLogger.Log($"EvalEnc: final Ready={ready}", ClientLogLevel.Debug);
            return ready;
        }

        /// <summary>
        /// Initializes the encryption pipeline by validating prerequisites, 
        /// ensuring local key material is present,
        /// publishing the local public key in multi-client scenarios, 
        /// injecting it in solo mode for self-decryption,
        /// synchronizing peer keys through server requests, 
        /// and finally updating runtime flags and UI bindings to reflect whether 
        /// encryption is fully ready. 
        /// This method guarantees that both outgoing and incoming messages 
        /// can be securely processed once all required keys are available.
        /// </summary>

        public async Task<bool> InitializeEncryptionAsync(CancellationToken cancellationToken)
        {
            /// <summary> Validates that ViewModel and LocalUser are available. </summary>
            if (_viewModel == null || _viewModel.LocalUser == null)
            {
                ClientLogger.Log("Initializing of encryption aborted — ViewModel or LocalUser not initialized.", ClientLogLevel.Error);
                return false;
            }

            /// <summary> Ensures that LocalUser has key material from EncryptionHelper. </summary>
            if ((_viewModel.LocalUser.PublicKeyDer == null || _viewModel.LocalUser.PublicKeyDer.Length == 0) &&
                (EncryptionHelper.PublicKeyDer != null && EncryptionHelper.PublicKeyDer.Length > 0))
            {
                _viewModel.LocalUser.PublicKeyDer = EncryptionHelper.PublicKeyDer;
                ClientLogger.Log("Materialized local public key from EncryptionHelper.", ClientLogLevel.Debug);
            }
            if ((_viewModel.LocalUser.PrivateKeyDer == null || _viewModel.LocalUser.PrivateKeyDer.Length == 0) &&
                (EncryptionHelper.PrivateKeyDer != null && EncryptionHelper.PrivateKeyDer.Length > 0))
            {
                _viewModel.LocalUser.PrivateKeyDer = EncryptionHelper.PrivateKeyDer;
                ClientLogger.Log("Materialized local private key from EncryptionHelper.", ClientLogLevel.Debug);
            }

            /// <summary> Injects the local key into KnownPublicKeys in solo mode. </summary>
            if (_viewModel != null && _viewModel.Users.Count <= 1 && _viewModel.LocalUser.PublicKeyDer?.Length > 0)
            {
                lock (KnownPublicKeys)
                {
                    KnownPublicKeys[_viewModel.LocalUser.UID] = _viewModel.LocalUser.PublicKeyDer;
                }
            }

            /// <summary> Synchronizes peer keys and handles solo short-circuit internally. </summary>
            bool syncPeerKeysOk = await SyncKeysAsync(cancellationToken).ConfigureAwait(false);

            /// <summary> Evaluates the final state and propagates it to the UI. </summary>
            bool finalStateOfEncryption = EvaluateEncryptionState();

            _uiDispatcherInvoke(() =>
            {
                if (_viewModel != null)
                {
                    SetEncryptionReady(finalStateOfEncryption);
                    SetSyncing(!finalStateOfEncryption);

                    // Encryption state is propagated only via IsEncryptionReady
                }
            });


            ClientLogger.Log($"Initializing of encryption completed — SyncPeerKeysOk={syncPeerKeysOk}, EncryptionReady={finalStateOfEncryption}", ClientLogLevel.Info);
            return syncPeerKeysOk && finalStateOfEncryption;
        }

        /// <summary>
        /// Marks the pipeline ready for encryption/decryption after handshake.
        /// Updates LocalUser and KnownPublicKeys with the provided public key.
        /// </summary>
        public void MarkReadyForSession(Guid uid, byte[] publicKeyDer)
        {
            /// <summary> Validates that a non-empty public key is provided </summary>
            if (publicKeyDer == null || publicKeyDer.Length == 0)
                throw new InvalidOperationException("Public key not initialized");

            /// <summary> Updates LocalUser with the handshake key </summary>
            _viewModel.LocalUser.PublicKeyDer = publicKeyDer;

            /// <summary> Injects the key into KnownPublicKeys for consistency </summary>
            lock (KnownPublicKeys)
            {
                KnownPublicKeys[uid] = publicKeyDer;
            }

            /// <summary> Marks encryption as ready </summary>
            IsEncryptionReady = true;

            /// <summary> Logs handshake completion with key length </summary>
            ClientLogger.Log(
                $"MarkReadyForSession — UID={uid}, PublicKeyLen={publicKeyDer.Length}",
                ClientLogLevel.Debug
            );
        }

        /// <summary>
        /// Sets the encryption ready flag and notifies listeners if changed.
        /// </summary>
        public void SetEncryptionReady(bool ready)
        {
            if (IsEncryptionReady == ready)
            {
                return;
            }

            IsEncryptionReady = ready;
            StateChanged?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// Sets the syncing flag and notifies listeners if changed.
        /// </summary>
        public void SetSyncing(bool syncing)
        {
            if (IsSyncingKeys == syncing) 
            {
                return;
            }

            IsSyncingKeys = syncing;
            StateChanged?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// Starts the encryption pipeline asynchronously.
        /// Cancels any previous run, 
        /// creates a fresh CancellationToken,
        /// and runs initialization in the background.
        /// Updates flags via dispatcher so the UI stays consistent.
        /// </summary>
        /// <returns>true if initialization succeeds; otherwise false</returns>
        public async Task<bool> StartEncryptionPipelineBackground()
        {
            /// <summary> Cancels and disposes any previous run. </summary>
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            try
            {
                /// <summary> Notifies UI that syncing has started. </summary>
                _uiDispatcherInvoke(() =>
                {
                    IsSyncingKeys = true;
                    IsEncryptionReady = false;
                });

                /// <summary> Runs centralized initialization pipeline. </summary>
                bool result = await InitializeEncryptionAsync(token).ConfigureAwait(false);

                /// <summary> Updates final state after initialization. </summary>
                _uiDispatcherInvoke(() =>
                {
                    bool encryptionReady = EvaluateEncryptionState();
                    IsEncryptionReady = encryptionReady;
                    IsSyncingKeys = !encryptionReady;
                });

                return result;
            }
            catch (OperationCanceledException)
            {
                /// <summary> Handles cancellation gracefully. </summary>
                ClientLogger.Log("Encryption pipeline cancelled.", ClientLogLevel.Warn);

                _uiDispatcherInvoke(() =>
                {
                    IsSyncingKeys = false;
                    IsEncryptionReady = false;
                });

                return false;
            }
            catch (Exception ex)
            {
                /// <summary> Logs fatal error and rolls back settings. </summary>
                ClientLogger.Log($"Encryption pipeline failed: {ex.GetBaseException().Message}", ClientLogLevel.Error);

                Settings.Default.UseEncryption = false;
                try { Settings.Default.Save(); } catch { }

                _uiDispatcherInvoke(() =>
                {
                    IsSyncingKeys = false;
                    IsEncryptionReady = false;
                });

                return false;
            }
        }

        /// <summary>
        /// Synchronizes public keys across connected peers.
        /// Publishes the local public key to the server,
        /// requests missing peer keys, and waits until all are received or timeout occurs.
        /// Handles solo mode short-circuit when no peers are present.
        /// Updates encryption readiness flags once synchronization completes.
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
                    IsSyncingKeys = false;
                });
                return false;
            }

            // Marks syncing state as active and encryption as not ready.
            _uiDispatcherInvoke(() =>
            {
                IsSyncingKeys = true;
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
                        IsSyncingKeys = false;
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
                        IsSyncingKeys = false;
                    });
                    return false;
                }

                await _clientConn.SendPublicKeyToServerAsync(_viewModel.LocalUser.UID, localKey, _viewModel.LocalUser.UID,
                    cancellationToken).ConfigureAwait(false);

                // Identifies peers whose public keys are missing.
                List<Guid> missingKeys;
                lock (KnownPublicKeys)
                {
                    missingKeys = peerIds.Where(uid => !KnownPublicKeys.ContainsKey(uid)).ToList();
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
                    lock (KnownPublicKeys)
                    {
                        var stillMissing = peerIds.Where(uid => !KnownPublicKeys.ContainsKey(uid)).ToList();
                        if (stillMissing.Count == 0)
                        {
                            _uiDispatcherInvoke(() =>
                            {
                                IsEncryptionReady = true;
                                IsSyncingKeys = false;
                            });
                            break;
                        }
                    }

                    if (DateTime.UtcNow - startTime > timeout)
                    {
                        _uiDispatcherInvoke(() =>
                        {
                            IsEncryptionReady = false;
                            IsSyncingKeys = false;
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
            finally
            {
                _uiDispatcherInvoke(() =>
                {
                    IsSyncingKeys = false;
                });
            }
        }
    }
}

