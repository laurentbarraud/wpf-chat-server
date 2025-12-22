/// <file>EncryptionPipeline.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 22th, 2025</date>

using chat_client.MVVM.ViewModel;
using chat_client.Net;
using chat_client.Properties;
using Microsoft.VisualBasic.ApplicationServices;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading;
using System.Windows;

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
        /// Flag to ensure we publish the local key only once
        /// </summary>
        private bool _localKeyPublished;

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
            /// <summary> Cancels and disposes any active pipeline </summary>
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

            /// <summary> Clears peer keys and resets local publication state </summary>
            KnownPublicKeys.Clear();
            _localKeyPublished = false;

            _viewModel.ResetEncryptionPipelineAndUI();
            
            /// <summary> Persists disabled state in settings </summary>
            Settings.Default.UseEncryption = false;
            
            try 
            { 
                Settings.Default.Save(); 
            } 
            
            catch { }

            /// <summary> Logs the disable action for diagnostics </summary>
            ClientLogger.Log("Encryption disabled via EncryptionPipeline.DisableEncryption().", ClientLogLevel.Info);
        }

        /// <summary>
        /// Evaluates the encryption readiness state of the pipeline.
        /// This method ensures that a client does not prematurely mark itself as "ready"
        /// before all required peer public keys have been received and registered.
        /// • If encryption is disabled or the local user is not initialized, readiness is false.  
        /// • In solo mode (only one user), readiness is true if a local public key exists.  
        /// • In multi-user mode, readiness is true only if all peer keys are present in KnownPublicKeys.  
        /// • Missing keys are logged explicitly to aid debugging.
        /// • Updates UI flags (EncryptionReady, Syncing) via dispatcher to keep bindings consistent.  
        /// • Returns the final readiness flag to the caller.  
        /// </summary>
        public bool EvaluateEncryptionState()
        {
            /// <summary> Initializes readiness flag to false by default. </summary>
            bool isEncryptionReady = false;

            /// <summary> Encryption disabled or local user not initialized. </summary>
            if (!Settings.Default.UseEncryption || _viewModel.LocalUser == null)
            {
                ClientLogger.Log("EvaluateEncryptionState: encryption disabled or local user not initialized.", ClientLogLevel.Info);
            }
            /// <summary>
            /// Solo mode (only one user in the session).
            /// Ready if a local public key exists.
            /// </summary>
            else if (_viewModel.Users.Count <= 1)
            {
                if (_viewModel.LocalUser.PublicKeyDer != null && _viewModel.LocalUser.PublicKeyDer.Length > 0)
                {
                    ClientLogger.Log("EvaluateEncryptionState: solo mode with local key — ready.", ClientLogLevel.Info);
                    isEncryptionReady = true;
                }
                else if (EncryptionHelper.PublicKeyDer != null && EncryptionHelper.PublicKeyDer.Length > 0)
                {
                    ClientLogger.Log("EvaluateEncryptionState: solo mode using EncryptionHelper key — ready.", ClientLogLevel.Info);
                    isEncryptionReady = true;
                }
                else
                {
                    ClientLogger.Log("EvaluateEncryptionState: solo mode but local key missing — not ready.", ClientLogLevel.Warn);
                }
            }
            /// <summary>
            /// Multi-user mode (two or more users).
            /// Readiness requires that all peer public keys are present.
            /// </summary>
            else
            {
                /// <summary> Collects peer UIDs excluding the local user. </summary>
                List<Guid> peerUids = _viewModel.Users
                    .Where(u => u.UID != _viewModel.LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                /// <summary> Computes missing keys by comparing peer UIDs with KnownPublicKeys. </summary>
                List<Guid> missingKeys;
                lock (KnownPublicKeys)
                {
                    missingKeys = peerUids.Except(KnownPublicKeys.Keys).ToList();
                }

                /// <summary>
                /// Determines readiness based on presence of all peer keys.
                /// If any keys are missing, readiness remains false.
                /// </summary>
                if (missingKeys.Count == 0)
                {
                    ClientLogger.Log("EvaluateEncryptionState: all peer keys present — ready.", ClientLogLevel.Info);
                    isEncryptionReady = true;
                }
                else
                {
                    ClientLogger.Log($"EvaluateEncryptionState: missing keys for {string.Join(", ", missingKeys)}", ClientLogLevel.Debug);

                    /// <summary> Explicitly forces not ready until all keys are present </summary>
                    isEncryptionReady = false; 
                }
            }

            /// <summary>
            /// Updates pipeline flags on the dispatcher thread.
            /// • EncryptionReady reflects readiness state.  
            /// • Syncing is true when readiness is false (still waiting for keys).  
            /// </summary>
            _uiDispatcherInvoke(() =>
            {
                SetEncryptionReady(isEncryptionReady);
                SetSyncing(!isEncryptionReady);
            });

            /// <summary>
            /// Logs the final evaluation result for debugging and traceability.
            /// </summary>
            ClientLogger.Log($"EvaluateEncryptionState result — Ready={isEncryptionReady}", ClientLogLevel.Debug);

            /// <summary>
            /// Returns readiness flag to caller.
            /// </summary>
            return isEncryptionReady;
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

            /// <summary>
            /// Publishes the local public key once per session in multi-client mode.
            /// Triggered only if the pipeline is ready, the key is present, and there are multiple users.
            /// </summary>
            if (_viewModel?.EncryptionPipeline?.IsEncryptionReady == true && !_localKeyPublished
                && _viewModel.LocalUser.PublicKeyDer?.Length > 0  && _viewModel.Users.Count > 1)
            {
                bool sentPublicKeyToServer = await _clientConn.SendPublicKeyToServerAsync(_viewModel.LocalUser.UID,
                _viewModel.LocalUser.PublicKeyDer ?? Array.Empty<byte>(), _viewModel.LocalUser.UID, 
                cancellationToken).ConfigureAwait(false);

                if (sentPublicKeyToServer)
                {
                    _localKeyPublished = true;
                    ClientLogger.Log("InitializeEncryptionAsync: local public key published (multi-client).", ClientLogLevel.Debug);
                }
                else
                {
                    ClientLogger.Log("InitializeEncryptionAsync: local public key publication failed.", ClientLogLevel.Warn);
                }
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
            /// <summary>
            /// Validates that encryption prerequisites are present before proceeding.
            /// Falls back to false if local key material is missing.
            /// </summary>
            if (_viewModel?.LocalUser?.PublicKeyDer == null || _viewModel.LocalUser.PublicKeyDer.Length == 0)
            {
                _uiDispatcherInvoke(() =>
                {
                    IsEncryptionReady = false;
                    IsSyncingKeys = false;
                });
                return false;
            }

            /// <summary> Marks syncing state as active and encryption as not ready. </summary>
            _uiDispatcherInvoke(() =>
            {
                IsSyncingKeys = true;
                IsEncryptionReady = false;
            });

            try
            {
                /// <summary> Collects peer IDs excluding the local user. </summary>
                var peerIds = _viewModel.Users
                    .Where(u => u.UID != _viewModel.LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                /// <summary> Solo mode short-circuit: ready immediately if local key exists. </summary>
                if (peerIds.Count == 0 && _viewModel.LocalUser.PublicKeyDer?.Length > 0)
                {
                    _uiDispatcherInvoke(() =>
                    {
                        IsEncryptionReady = true;
                        IsSyncingKeys = false;
                    });
                    ClientLogger.Log("SyncKeysAsync: solo mode detected — encryption ready immediately.", ClientLogLevel.Info);
                    return true;
                }

                /// <summary>
                /// Publishes the local public key to the server for distribution in multi-client mode.
                /// Ensures that the payload is never null.
                /// </summary>
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

                /// <summary> Identifies peers whose public keys are missing. </summary>
                List<Guid> missingKeys;
                lock (KnownPublicKeys)
                {
                    missingKeys = peerIds.Where(uid => !KnownPublicKeys.ContainsKey(uid)).ToList();
                }

                ClientLogger.Log($"SyncKeysAsync: peers={peerIds.Count}, missing={missingKeys.Count}", ClientLogLevel.Debug);

                /// <summary> Requests missing keys sequentially from peers. </summary>
                foreach (var uid in missingKeys)
                {
                    await _clientConn.SendRequestToPeerForPublicKeyAsync(uid, cancellationToken);
                }

                /// <summary> Defines timeout and start time for key synchronization. </summary>
                var timeout = TimeSpan.FromSeconds(5);
                var startTime = DateTime.UtcNow;

                /// <summary> Loops until all peer keys are received or timeout occurs. </summary>
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
            catch (OperationCanceledException) { throw; }
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

