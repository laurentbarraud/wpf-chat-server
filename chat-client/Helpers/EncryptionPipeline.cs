/// <file>EncryptionPipeline.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 27th, 2025</date>

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
        /// State flags exposed to the UI
        /// </summary>
        public bool IsEncryptionReady { get; set; }
        public bool IsSyncingKeys { get; set; }

        /// <summary>
        /// Known public keys (peer GUID → DER bytes)
        /// </summary>
        public Dictionary<Guid, byte[]> KnownPublicKeys { get; } = new();

        public byte[] PublicKeyDer { get; set; }

        /// <summary> Holds the DER-encoded RSA public key associated with the current session </summary>
        public byte[] SessionPublicKey { get; private set; } = Array.Empty<byte>();

        /// <summary> Stores the unique session identifier (GUID) assigned to this pipeline </summary>
        public Guid SessionUid { get; private set; }

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
        /// Cancels any running pipeline, 
        /// disposes the cancellation source,
        /// clears all local and peer key material,
        /// resets the encryption flags,
        /// persists the disabled state in settings 
        /// and notifies the UI.
        /// This method is idempotent : it can be called multiple times safely.
        /// </summary>
        public void DisableEncryption()
        {
            try 
            {
                // Cancels and dispose any active pipeline
                _cts?.Cancel(); 
            } 
            catch 
            {  
            }
            _cts?.Dispose();
            _cts = null;

            // Clears all known peer keys
            _viewModel.KnownPublicKeys.Clear();

            // Resets local key publication state
            _localKeyPublished = false;

            // Clears local key material if available
            if (_viewModel.LocalUser != null)
            {
                _viewModel.LocalUser.PublicKeyDer = Array.Empty<byte>();
                _viewModel.LocalUser.PrivateKeyDer = Array.Empty<byte>();
            }
            
            EncryptionHelper.ClearPrivateKey();

            // Persists disabled state in settings
            Settings.Default.UseEncryption = false;
            try 
            { 
                Settings.Default.Save(); 
            } 
            catch 
            { }

            // Resets flags
            IsEncryptionReady = false;
            IsSyncingKeys = false;

            // Resets encryption flags via ViewModel helper method
            _uiDispatcherInvoke(() =>
            {
                _viewModel.ResetEncryptionFlags();
            });

            ClientLogger.Log("Encryption disabled via EncryptionPipeline.Disable().", ClientLogLevel.Info);
        }

        /// <summary>
        /// Evaluates whether encryption can be considered ready based on current peers and known keys.
        /// • Disabled: always false.
        /// • Solo mode: ready immediately if encryption is enabled and local key exists.
        /// • Multi-client: ready only if all peers have a registered public key.
        /// Updates UI flags on the dispatcher to keep visuals consistent.
        /// </summary>
        /// <returns>True if encryption is enabled and all required peer keys are present; otherwise false.</returns>
        public bool EvaluateEncryptionState()
        {
            // Initializes readiness flag to false by default
            bool isEncryptionReady = false;

            // Checks if encryption is globally enabled and if local user exists
            if (!Settings.Default.UseEncryption || _viewModel.LocalUser == null)
            {
                ClientLogger.Log("EvaluateEncryptionState checks encryption disabled or local user not initialized.", ClientLogLevel.Info);
                isEncryptionReady = false;
            }
            else
            {
                // Detects solo mode: only local user present
                if (_viewModel.Users.Count <= 1)
                {
                    // Verifies that local public key exists before declaring readiness
                    bool hasLocalKey = _viewModel.LocalUser.PublicKeyDer != null && _viewModel.LocalUser.PublicKeyDer.Length > 0;
                    if (hasLocalKey)
                    {
                        ClientLogger.Log("EvaluateEncryptionState detects solo mode with local key — encryption is considered ready.", ClientLogLevel.Info);
                        isEncryptionReady = true;
                    }
                    else
                    {
                        ClientLogger.Log("EvaluateEncryptionState detects solo mode but local key missing — encryption not ready.", ClientLogLevel.Warn);
                        isEncryptionReady = false;
                    }
                }
                else
                {
                    // Collects peer UIDs excluding local user
                    List<Guid> peerUids = _viewModel.Users
                        .Where(u => u.UID != _viewModel.LocalUser.UID)
                        .Select(u => u.UID)
                        .ToList();

                    // Computes missing keys by comparing peer UIDs with known public keys
                    List<Guid> missingKeys;
                    lock (_viewModel.KnownPublicKeys)
                    {
                        missingKeys = peerUids.Except(_viewModel.KnownPublicKeys.Keys).ToList();
                    }

                    // If missing keys exist, encryption is not ready
                    if (missingKeys.Count > 0)
                    {
                        ClientLogger.Log($"EvaluateEncryptionState detects missing keys for: {string.Join(", ", missingKeys)}", ClientLogLevel.Debug);
                        isEncryptionReady = false;
                    }
                    else
                    {
                        // All peer keys are present, encryption is ready
                        ClientLogger.Log("EvaluateEncryptionState confirms all peer keys are present — encryption ready.", ClientLogLevel.Info);
                        isEncryptionReady = true;
                    }
                }
            }

            // Updates UI flags atomically on the UI thread
            _uiDispatcherInvoke(() =>
            {
                IsEncryptionReady = isEncryptionReady;
            });

            // Logs the final result of the evaluation
            ClientLogger.Log($"EvaluateEncryptionState result — Ready={isEncryptionReady}", ClientLogLevel.Debug);

            // Returns the readiness flag
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

            // Synchronizes with local key if not already set
            if (PublicKeyDer == null || PublicKeyDer.Length == 0)
                PublicKeyDer = publicKeyDer;

            // Marks encryption as ready
            IsEncryptionReady = true;

            Debug.WriteLine("[INFO] EncryptionPipeline marked ready for session.");
        }

        /// <summary>
        /// Starts the encryption pipeline asynchronously.
        /// Cancels any previous run, creates a fresh CancellationToken,
        /// and runs initialization in the background.
        /// The pipeline updates its internal flags, while the ViewModel
        /// remains responsible for notifying the UI.
        /// </summary>
        public async Task<bool> StartEncryptionPipelineBackground()
        {
            // Cancels previous run if any
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            try
            {
                // Updates internal flags (UI notification is done by ViewModel)
                _uiDispatcherInvoke(() =>
                {
                    IsSyncingKeys = true;
                    IsEncryptionReady = false;
                });

                // Runs centralized initialization pipeline
                bool result = await InitializeEncryptionAsync(token).ConfigureAwait(false);

                // Final state after initialization
                _uiDispatcherInvoke(() =>
                {
                    bool isEncryptionReady = EvaluateEncryptionState();
                    IsEncryptionReady = isEncryptionReady;
                    IsSyncingKeys = !isEncryptionReady;
                });

                return result;
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Encryption pipeline cancelled.");

                _uiDispatcherInvoke(() =>
                {
                    IsSyncingKeys = false;
                    IsEncryptionReady = false;
                });

                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Encryption pipeline failed: {ex.GetBaseException().Message}");

                // Rolls back setting on fatal error
                Settings.Default.UseEncryption = false;
                try { Settings.Default.Save(); } catch { /* swallow */ }

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
        /// • Marks syncing state so the UI can notify the user.
        /// • Collects all peer IDs except the local one.
        /// • If solo mode (no peers), encryption is ready right away.
        /// • Requests missing peer keys sequentially.
        /// • Waits until all keys are received or a timeout occurs.
        /// </summary>
        /// <returns>true when all peer keys are present</returns>
        public async Task<bool> SyncKeysAsync(CancellationToken cancellationToken)
        {
            // Exits early if encryption is disabled
            if (!Settings.Default.UseEncryption)
            {
                IsEncryptionReady = false;
                IsSyncingKeys = false;
                return false;
            }

            // Callback used to run actions on the UI thread
            _uiDispatcherInvoke(() =>
            {
                // Notifies UI that syncing has started
                IsSyncingKeys = true;
                IsEncryptionReady = false;
            });

            try
            {
                // Snapshots of peer IDs (excluding local user)
                var lstPeerIds = _viewModel.Users
                    .Where(u => u.UID != _viewModel.LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                /// <summary>
                /// Solo mode: if there are no peers, encryption is considered ready immediately.
                /// This prevents waiting forever for non-existent keys.
                /// </summary>
                if (lstPeerIds.Count == 0)
                {
                    // Flips flags on UI thread for visual consistency
                    _uiDispatcherInvoke(() =>
                    {
                        IsEncryptionReady = true;
                        IsSyncingKeys = false;
                    });

                    ClientLogger.Log("SyncKeysAsync: solo mode detected — encryption ready immediately.", ClientLogLevel.Info);
                    return true;
                }

                // Identifies missing keys
                List<Guid> missingKeys;
                lock (_viewModel.KnownPublicKeys)
                {
                    missingKeys = lstPeerIds
                        .Where(uid => !_viewModel.KnownPublicKeys.ContainsKey(uid))
                        .ToList();
                }

                ClientLogger.Log($"SyncKeysAsync: numberOfPeers={lstPeerIds.Count}, missingKeys={missingKeys.Count}",
                    ClientLogLevel.Debug
                );

                // Requests missing keys sequentially
                foreach (var uid in missingKeys)
                {
                    await _clientConn.SendRequestToPeerForPublicKeyAsync(uid, cancellationToken);
                }

                // Waits until all missing keys are received or timeout
                var timeout = TimeSpan.FromSeconds(5);
                var start = DateTime.UtcNow;

                while (true)
                {
                    /// <summary>"lock" is like saying: only one person can touch this box of keys at a time.</summary>
                    lock (_viewModel.KnownPublicKeys)

                    {
                        /// <summary> We look at all friends (peer IDs) and make a list of those whose key we do not have yet.</summary>
                        var stillMissing = lstPeerIds
                            .Where(uid => !_viewModel.KnownPublicKeys.ContainsKey(uid))
                            .ToList();

                        ///<summary> If the list of missing keys is empty, it means we now have all the keys.</summary>
                        if (stillMissing.Count == 0)

                        {
                            // Lock icon in the UI will turn colored with animation.
                            IsEncryptionReady = true;

                            break;
                            
                        }
                    }

                    // If too much time has passed since we started waiting
                    if (DateTime.UtcNow - start > timeout)

                    {
                        IsEncryptionReady = false;

                        ClientLogger.Log("SyncKeysAsync: timeout waiting for peer keys", ClientLogLevel.Warn);
                    
                       break;
                    }

                    // Avoids wasting energy looping too fast
                    await Task.Delay(200, cancellationToken);
                }


                return IsEncryptionReady;
            }
            catch (OperationCanceledException)
            {
                // Preserves cancellation semantics
                throw;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"SyncKeys failed: {ex.Message}", ClientLogLevel.Error);
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

