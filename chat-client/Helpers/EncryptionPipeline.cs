/// <file>EncryptionPipeline.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 28th, 2025</date>

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
        /// DER-encoded public key associated with the current session.
        /// Used to evaluate local readiness and decrypt inbound messages.
        /// </summary>
        public byte[] SessionPublicKey { get; private set; } = Array.Empty<byte>();

        /// <summary>
        /// Unique session identifier (GUID) assigned to this pipeline.
        /// </summary>
        public Guid SessionUid { get; private set; }

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

            // Initializes local public key material once at construction
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
            EncryptionHelper.ClearPrivateKey();

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
        /// Evaluates whether encryption can be considered ready based on current peers and known keys.
        /// • Disabled: always false.
        /// • Solo mode: ready immediately if encryption is enabled and session key exists.
        /// • Multi-client: ready only if all peers have a registered public key.
        /// Updates pipeline flags via dispatcher so the UI stays consistent.
        /// </summary>
        /// <returns>True if encryption is enabled and all required peer keys are present; otherwise false.</returns>
        public bool EvaluateEncryptionState()
        {
            /// <summary> Initializes readiness flag to false by default </summary>
            bool isEncryptionReady = false;

            /// <summary> Checks if encryption is globally enabled and if local user exists </summary>
            if (!Settings.Default.UseEncryption || _viewModel.LocalUser == null)
            {
                ClientLogger.Log("EvaluateEncryptionState: encryption disabled or local user not initialized.", ClientLogLevel.Info);
                isEncryptionReady = false;
            }
            else
            {
                /// <summary> Detects solo mode: only local user present </summary>
                if (_viewModel.Users.Count <= 1)
                {
                    /// <summary> Verifies that session public key exists before declaring readiness </summary>
                    bool hasSessionKey = SessionPublicKey != null && SessionPublicKey.Length > 0;
                    if (hasSessionKey)
                    {
                        ClientLogger.Log("EvaluateEncryptionState: solo mode with session key — ready.", ClientLogLevel.Info);
                        isEncryptionReady = true;
                    }
                    else
                    {
                        ClientLogger.Log("EvaluateEncryptionState: solo mode but session key missing — not ready.", ClientLogLevel.Warn);
                        isEncryptionReady = false;
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

                    /// <summary> If missing keys exist, encryption is not ready </summary>
                    if (missingKeys.Count > 0)
                    {
                        ClientLogger.Log($"EvaluateEncryptionState: missing keys for {string.Join(", ", missingKeys)}", ClientLogLevel.Debug);
                        isEncryptionReady = false;
                    }
                    else
                    {
                        /// <summary> All peer keys are present → encryption ready </summary>
                        ClientLogger.Log("EvaluateEncryptionState: all peer keys present — ready.", ClientLogLevel.Info);
                        isEncryptionReady = true;
                    }
                }
            }

            /// <summary>
            /// Update pipeline flags on the dispatcher thread.
            /// SetEncryptionReady/SetSyncing trigger StateChanged,
            /// which makes the ViewModel raise OnPropertyChanged,
            /// so WPF bindings refresh automatically.
            /// </summary>
            _uiDispatcherInvoke(() =>
            {
                SetEncryptionReady(isEncryptionReady);
                SetSyncing(!isEncryptionReady);
            });

            /// <summary> Log the final evaluation result </summary>
            ClientLogger.Log($"EvaluateEncryptionState result — Ready={isEncryptionReady}", ClientLogLevel.Debug);

            /// <summary> Return readiness flag to caller </summary>
            return isEncryptionReady;
        }



        /// <summary>
        /// • Publish the local public key once per session.
        /// • Synchronize peer keys (handles solo short-circuit internally).
        /// • Validate readiness and update UI state.
        /// </summary>
        /// <returns>Returns true if encryption is enabled and peers are fully ready (or solo is detected).</returns>
        public async Task<bool> InitializeEncryptionAsync(CancellationToken cancellationToken)
        {
            // Guards against null ViewModel or LocalUser before proceeding
            if (_viewModel == null)
            {
                ClientLogger.Log("InitializeEncryptionAsync aborted — ViewModel not initialized.", ClientLogLevel.Error);
                return false;
            }

            if (_viewModel.LocalUser == null)
            {
                ClientLogger.Log("InitializeEncryptionAsync aborted — LocalUser not initialized.", ClientLogLevel.Warn);
                return false;
            }

            // Publishes the local public key only once per session
            if (!_localKeyPublished)
            {
                if (_viewModel.LocalUser.PublicKeyDer != null && _viewModel.LocalUser.PublicKeyDer.Length > 0)
                {
                    try
                    {
                        // Publishes the local public key; server redistributes to peers who need it
                        await _clientConn.SendPublicKeyToServerAsync(_viewModel.LocalUser.UID, _viewModel.LocalUser.PublicKeyDer,
                            cancellationToken).ConfigureAwait(false);

                        _localKeyPublished = true;
                        ClientLogger.Log("InitializeEncryptionAsync: local public key published.", ClientLogLevel.Debug);
                    }
                    catch (Exception ex)
                    {
                        ClientLogger.Log($"InitializeEncryptionAsync failed to publish local key: {ex.Message}", ClientLogLevel.Error);
                        return false;
                    }
                }
                else
                {
                    ClientLogger.Log("InitializeEncryptionAsync: local public key not yet available, skipping publish.", ClientLogLevel.Warn);
                }
            }

            // Synchronizes peer keys (handles solo mode internally)
            bool syncOk = false;
            try
            {
                syncOk = await SyncKeysAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"InitializeEncryptionAsync failed during SyncKeysAsync: {ex.Message}", ClientLogLevel.Error);
                return false;
            }

            // Evaluates final state for consistency and updates UI flags
            bool finalStateOfEncryption = EvaluateEncryptionState();

            ClientLogger.Log($"InitializeEncryptionAsync completed — SyncOk={syncOk}, Ready={finalStateOfEncryption}",
                ClientLogLevel.Info);

            // Returns true only if synchronization succeeded and encryption is ready
            return syncOk && finalStateOfEncryption;
        }

        /// <summary>
        /// Marks the pipeline ready for encryption/decryption after handshake.
        /// Validates the provided public key and updates session state.
        /// </summary>
        /// <param name="uid">Unique session identifier (GUID).</param>
        /// <param name="publicKeyDer">DER-encoded RSA public key for the session.</param>
        public void MarkReadyForSession(Guid uid, byte[] publicKeyDer)
        {
            if (publicKeyDer == null || publicKeyDer.Length == 0)
                throw new InvalidOperationException("Public key not initialized");

            // Updates session identifiers
            SessionUid = uid;
            SessionPublicKey = publicKeyDer;

            // Ensures PublicKeyDer is also set for InitializeEncryptionAsync
            PublicKeyDer = publicKeyDer;

            // Marks encryption as ready
            IsEncryptionReady = true;

            // Detailed log for debugging key presence
            ClientLogger.Log(
                $"MarkReadyForSession — UID={uid}, SessionKeyLen={SessionPublicKey?.Length}, PublicKeyLen={PublicKeyDer?.Length}",
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
            /// <summary> Cancels and disposes any previous run </summary>
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            try
            {
                /// <summary> Notifies UI that syncing has started </summary>
                _uiDispatcherInvoke(() =>
                {
                    IsSyncingKeys = true;
                    IsEncryptionReady = false;
                });

                /// <summary> Runs centralized initialization pipeline </summary>
                bool result = await InitializeEncryptionAsync(token).ConfigureAwait(false);

                /// <summary> Updates final state after initialization </summary>
                _uiDispatcherInvoke(() =>
                {
                    bool ready = EvaluateEncryptionState();
                    IsEncryptionReady = ready;
                    IsSyncingKeys = !ready;
                });

                return result;
            }
            catch (OperationCanceledException)
            {
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
                ClientLogger.Log($"Encryption pipeline failed: {ex.GetBaseException().Message}", ClientLogLevel.Error);

                /// <summary> Rolls back settings on fatal error </summary>
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

                /// <summary> Detects solo mode and marks encryption as ready immediately </summary>
                if (peerIds.Count == 0)
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

