/// <file>EncryptionPipeline.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 1st, 2025</date>

using chat_client.MVVM.ViewModel;
using chat_client.Net;
using chat_client.Properties;
using Microsoft.VisualBasic.ApplicationServices;
using System;
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
    public class EncryptionPipeline
    {
        // PRIVATE FIELDS

        /// <summary>
        /// Cancellation token source for the current pipeline run
        /// </summary>
        private CancellationTokenSource? _cts;

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
        /// State flags (single source of truth for encryption UI state).
        /// ViewModel subscribes to StateChanged to mirror these flags.
        /// </summary>
        public bool IsEncryptionReady { get; private set; }
        public bool IsSyncingKeys { get; private set; }

        /// <summary>
        /// Known public keys of peers (UID → DER bytes).
        /// Empty arrays are ignored and do not affect readiness.
        /// </summary>
        public Dictionary<Guid, byte[]> KnownPublicKeys { get; } = new();

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
            catch { }
            
            _cts?.Dispose();
            _cts = null;

            /// <summary> Clears peer keys and resets local publication state </summary>
            KnownPublicKeys.Clear();
            _localKeyPublished = false;

            /// <summary> Clears local key material if available </summary>
            if (_viewModel.LocalUser != null)
            {
                _viewModel.LocalUser.PublicKeyDer = Array.Empty<byte>();
                _viewModel.LocalUser.PrivateKeyDer = Array.Empty<byte>();
            }
            EncryptionHelper.ClearLocalPrivateKey();

            /// <summary> Persists disabled state in settings </summary>
            Settings.Default.UseEncryption = false;
            try { Settings.Default.Save(); } catch { }

            /// <summary>
            /// Reset flags in the pipeline.
            /// SetEncryptionReady/SetSyncing trigger StateChanged,
            /// which makes the ViewModel raise OnPropertyChanged,
            /// so WPF bindings refresh the UI automatically.
            /// </summary>
            SetEncryptionReady(false);
            SetSyncing(false);

            /// <summary> Logs the disable action for diagnostics </summary>
            ClientLogger.Log("Encryption disabled via EncryptionPipeline.DisableEncryption().", ClientLogLevel.Info);
        }

        /// <summary>
        /// Evaluates whether encryption can be considered ready.
        /// • Disabled: always false.
        /// • Solo mode: ready if LocalUser.PublicKeyDer exists.
        /// • Multi-client: ready only if all peers have a registered public key.
        /// Updates pipeline flags via dispatcher so the UI stays consistent.
        /// </summary>
        public bool EvaluateEncryptionState()
        {
            /// <summary> Initializes readiness flag to false by default </summary>
            bool isEncryptionReady = false;

            /// <summary> Checks if encryption is globally enabled and if local user exists </summary>
            if (!Settings.Default.UseEncryption || _viewModel.LocalUser == null)
            {
                ClientLogger.Log("EvaluateEncryptionState: encryption disabled or local user not initialized.", ClientLogLevel.Info);
            }
            else if (_viewModel.Users.Count <= 1)
            {
                /// <summary> Solo mode: ready if LocalUser.PublicKeyDer exists </summary>
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
            else
            {
                /// <summary> Collects peer UIDs excluding local user </summary>
                List<Guid> peerUids = _viewModel.Users
                    .Where(u => u.UID != _viewModel.LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                /// <summary> Computes missing keys by comparing peer UIDs with known public keys </summary>
                List<Guid> missingKeys;
                lock (KnownPublicKeys)
                {
                    missingKeys = peerUids.Except(KnownPublicKeys.Keys).ToList();
                }

                /// <summary> Determines readiness based on presence of all peer keys </summary>
                if (missingKeys.Count == 0)
                {
                    ClientLogger.Log("EvaluateEncryptionState: all peer keys present — ready.", ClientLogLevel.Info);
                    isEncryptionReady = true;
                }
                else
                {
                    ClientLogger.Log($"EvaluateEncryptionState: missing keys for {string.Join(", ", missingKeys)}", ClientLogLevel.Debug);
                }
            }

            /// <summary> Updates pipeline flags on the dispatcher thread </summary>
            _uiDispatcherInvoke(() =>
            {
                SetEncryptionReady(isEncryptionReady);
                SetSyncing(!isEncryptionReady);
            });

            /// <summary> Logs the final evaluation result </summary>
            ClientLogger.Log($"EvaluateEncryptionState result — Ready={isEncryptionReady}", ClientLogLevel.Debug);

            /// <summary> Returns readiness flag to caller </summary>
            return isEncryptionReady;
        }

        /// <summary>
        /// • Publish the local public key once per session (idempotent).
        /// • Synchronize peer keys (handles solo short-circuit internally).
        /// • Validate readiness and update UI state.
        /// </summary>
        public async Task<bool> InitializeEncryptionAsync(CancellationToken cancellationToken)
        {
            /// <summary> Ensures ViewModel and LocalUser are initialized </summary>
            if (_viewModel == null || _viewModel.LocalUser == null)
            {
                ClientLogger.Log("InitializeEncryptionAsync aborted — ViewModel or LocalUser not initialized.", ClientLogLevel.Error);
                return false;
            }

            /// <summary> Materializes local public key from EncryptionHelper if missing </summary>
            if ((_viewModel.LocalUser.PublicKeyDer == null || _viewModel.LocalUser.PublicKeyDer.Length == 0) &&
                (EncryptionHelper.PublicKeyDer != null && EncryptionHelper.PublicKeyDer.Length > 0))
            {
                _viewModel.LocalUser.PublicKeyDer = EncryptionHelper.PublicKeyDer;
                ClientLogger.Log("InitializeEncryptionAsync: materialized local public key from EncryptionHelper.", ClientLogLevel.Debug);
            }

            /// <summary> Publishes local public key once per session (guarded by UseEncryption) </summary>
            if (_viewModel.UseEncryption && !_localKeyPublished && _viewModel.LocalUser.PublicKeyDer?.Length > 0)
            {
                bool sentPublicKeyToServer = await _clientConn.SendPublicKeyToServerAsync(_viewModel.LocalUser.UID,
                    _viewModel.LocalUser.PublicKeyDer, cancellationToken).ConfigureAwait(false);

                if (sentPublicKeyToServer)
                {
                    _localKeyPublished = true;
                    ClientLogger.Log("InitializeEncryptionAsync: local public key published.", ClientLogLevel.Debug);
                }
                else
                {
                    ClientLogger.Log("InitializeEncryptionAsync: local public key publication failed.", ClientLogLevel.Warn);
                }
            }

            /// <summary> If solo mode is detected </summary>
            if (_viewModel.Users.Count <= 1 && _viewModel.LocalUser.PublicKeyDer?.Length > 0)
            {
                lock (KnownPublicKeys)
                {   /// <summary> Injects local key into KnownPublicKeys</summary>
                    KnownPublicKeys[_viewModel.LocalUser.UID] = _viewModel.LocalUser.PublicKeyDer;
                }
            }

            /// <summary> Synchronizes peer keys </summary>
            bool syncPeerKeysOk = await SyncKeysAsync(cancellationToken).ConfigureAwait(false);

            /// <summary> Evaluates final state and updates UI </summary>
            bool finalStateOfEncryption = EvaluateEncryptionState();

            ClientLogger.Log($"InitializeEncryptionAsync completed — SyncPeerKeysOk={syncPeerKeysOk}, EncryptionReady={finalStateOfEncryption}", ClientLogLevel.Info);

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
        /// Marks syncing state so the UI can notify the user.
        /// Collects all peer IDs except the local one.
        /// If solo mode (no peers), encryption is ready immediately.
        /// Requests missing peer keys sequentially.
        /// Waits until all keys are received or a timeout occurs.
        /// </summary>
        public async Task<bool> SyncKeysAsync(CancellationToken cancellationToken)
        {
            /// <summary> Ensures that encryption is enabled before proceeding </summary>
            if (!Settings.Default.UseEncryption)
            {
                _uiDispatcherInvoke(() =>
                {
                    IsEncryptionReady = false;
                    IsSyncingKeys = false;
                });
                return false;
            }

            /// <summary> Marks syncing state as active and encryption as not ready </summary>
            _uiDispatcherInvoke(() =>
            {
                IsSyncingKeys = true;
                IsEncryptionReady = false;
            });

            try
            {
                /// <summary> Collects peer IDs excluding the local user </summary>
                var peerIds = _viewModel.Users
                    .Where(u => u.UID != _viewModel.LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                /// <summary> Solo mode: marks encryption ready immediately if local key exists </summary>
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

                /// <summary> Identifies peers whose public keys are missing </summary>
                List<Guid> missingKeys;
                lock (KnownPublicKeys)
                {
                    missingKeys = peerIds
                        .Where(uid => !KnownPublicKeys.ContainsKey(uid))
                        .ToList();
                }

                ClientLogger.Log($"SyncKeysAsync: peers={peerIds.Count}, missing={missingKeys.Count}", ClientLogLevel.Debug);

                /// <summary> Requests missing keys sequentially from peers </summary>
                foreach (var uid in missingKeys)
                {
                    await _clientConn.SendRequestToPeerForPublicKeyAsync(uid, cancellationToken);
                }

                /// <summary> Defines timeout and start time for key synchronization </summary>
                var timeout = TimeSpan.FromSeconds(5);
                var startTime = DateTime.UtcNow;

                /// <summary> Loops until all peer keys are received or timeout occurs </summary>
                while (true)
                {
                    /// <summary> Locks dictionary access to check missing keys safely </summary>
                    lock (KnownPublicKeys)
                    {
                        var stillMissing = peerIds
                            .Where(uid => !KnownPublicKeys.ContainsKey(uid))
                            .ToList();

                        /// <summary> Marks encryption as ready when no keys are missing </summary>
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

                    /// <summary> Marks encryption as not ready when timeout is exceeded </summary>
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

                    /// <summary> Delays briefly before rechecking to avoid busy looping </summary>
                    await Task.Delay(200, cancellationToken);
                }

                /// <summary> Returns the final encryption readiness state </summary>
                return IsEncryptionReady;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                /// <summary> Logs unexpected errors during synchronization </summary>
                ClientLogger.Log($"SyncKeysAsync failed: {ex.Message}", ClientLogLevel.Error);
                return false;
            }
            finally
            {
                /// <summary> Resets syncing flag on the UI thread </summary>
                _uiDispatcherInvoke(() =>
                {
                    IsSyncingKeys = false;
                });
            }
        }
    }
}

