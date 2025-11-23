/// <file>EncryptionPipeline.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>November 22th, 2025</date>

using chat_client.MVVM.ViewModel;
using chat_client.Net;
using chat_client.Properties;
using Microsoft.VisualBasic.ApplicationServices;
using System;
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
        private readonly ClientConnection _server;

        /// <summary>
        /// Callback used to run actions on the UI thread, ensuring safe property updates.
        /// </summary>
        private readonly Action<Action> _uiDispatcherInvoke;

        /// <summary>
        /// Reference to the main view model, used to access user and peer information for encryption.
        /// </summary>
        private readonly MainViewModel _viewModel;

        /// <summary>
        /// Known public keys (peer GUID → DER bytes)
        /// </summary>
        public Dictionary<Guid, byte[]> KnownPublicKeys { get; } = new();

        /// <summary>
        /// State flags exposed to the UI
        /// </summary>
        public bool IsEncryptionReady { get; private set; }
        public bool IsSyncingKeys { get; private set; }

        /// <summary>
        /// Creates a new EncryptionPipeline.
        /// Takes one callback to run code on the UI thread.
        /// This keeps encryption logic separate while still updating the interface.
        /// </summary>
        public EncryptionPipeline(Action<Action> uiDispatcherInvoke)
        {
            _uiDispatcherInvoke = uiDispatcherInvoke;
        }

        /// <summary>
        /// Determines whether encryption can proceed by checking:
        ///  - if encryption is enabled in settings  
        ///  - if Local user and its public key are initialized  
        ///  - if all connected peers have published a valid public key  
        /// Uses a lock on the shared key dictionary to ensure thread safety
        /// and logs each decision point for detailed troubleshooting.
        /// </summary>
        /// <returns>True if encryption is fully ready (including solo mode); otherwise, false.</returns>
        public bool AreAllKeysReceived()
        {
            // Logs the current encryption setting for debugging
            ClientLogger.Log($"EvaluateEncryptionState: UseEncryption={Settings.Default.UseEncryption}, LocalUserReady={_viewModel.LocalUser != null}",
                ClientLogLevel.Debug);

            // Skips if encryption is disabled or if the local user is not initialized
            if (!Settings.Default.UseEncryption || _viewModel.LocalUser == null)
            {
                ClientLogger.Log("Skipping encryption readiness check — encryption disabled or local user not initialized.",
                    ClientLogLevel.Info);
                return false;
            }

            // Checks presence of the local public key
            bool hasLocalKey = _viewModel.LocalUser.PublicKeyDer != null && _viewModel.LocalUser.PublicKeyDer.Length > 0;
            ClientLogger.Log($"Local public key present: {hasLocalKey}", ClientLogLevel.Debug);

            if (!hasLocalKey)
            {
                ClientLogger.Log("Skipping encryption readiness check — local public key not yet generated.", ClientLogLevel.Info);
                return false;
            }

            // Handles solo mode where no other peers are connected
            if (_viewModel.Users.Count <= 1)        // Treats local user alone as ready
            {
                ClientLogger.Log("Solo mode detected — only local user; encryption considered ready.",
                    ClientLogLevel.Debug);

                ClientLogger.Log("Encryption is fully activated and ready (solo mode).",
                    ClientLogLevel.Info);
                return true;
            }

            // Declares the missingKeys list as Guid to match KnownPublicKeys keys
            List<Guid> missingKeys;

            // Locks the shared dictionary while computing missing entries
            lock (KnownPublicKeys)
            {
                var peerUids = _viewModel.Users.Select(u => u.UID).ToList();

                // Logs the list of peer UIDs as strings
                ClientLogger.Log($"Peer UIDs to verify: {string.Join(", ", peerUids.Select(g => g.ToString()))}",
                    ClientLogLevel.Debug);

                // Computes which GUIDs are missing from the KnownPublicKeys dictionary
                missingKeys = peerUids.Except(_viewModel.KnownPublicKeys.Keys).ToList();

                ClientLogger.Log($"Number of missing keys detected: {missingKeys.Count}",
                    ClientLogLevel.Debug);
                // Logs peer key dictionary size for diagnostics
                ClientLogger.Log($"KnownPublicKeys count={_viewModel.KnownPublicKeys.Count}, Users count={_viewModel.Users.Count}", ClientLogLevel.Debug);
            }

            // Logs and aborts if any peer keys are missing
            if (missingKeys.Count > 0)
            {
                // Converts missing GUIDs to strings for human-readable logging
                ClientLogger.Log($"Encryption not ready — missing keys for: {string.Join(", ", missingKeys.Select(g => g.ToString()))}",
                    ClientLogLevel.Debug);
                return false;
            }

            // All checks passed: logs activation and returns readiness
            ClientLogger.Log("Encryption is fully activated and ready.", ClientLogLevel.Info);
            return true;
        }


        /// <summary>
        /// Disables encryption immediately and safely.
        /// Cancels any running pipeline, disposes the cancellation source,
        /// clears all local and peer key material, resets the encryption flags,
        /// persists the disabled state in settings, and notifies the UI.
        /// </summary>
        public void DisableEncryption()
        {
            // Cancels and dispose any active pipeline
            try 
            {
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

            // Reset encryption flags via ViewModel helper method
            _uiDispatcherInvoke(() =>
            {
                _viewModel.ResetEncryptionFlags();
            });

            ClientLogger.Log("Encryption disabled via EncryptionPipeline.Disable().", ClientLogLevel.Info);
        }

        /// <summary>
        /// Evaluates whether encryption can be considered ready based on current peers and known keys.
        /// • Disabled: always false.
        /// • Solo mode: ready immediately if encryption is enabled.
        /// • Multi-client: ready only if all peers have a registered public key.
        /// Updates UI flags on the dispatcher to keep visuals consistent.
        /// </summary>
        /// <returns>True if encryption is enabled and all required peer keys are present; otherwise false.</returns>
        public bool EvaluateEncryptionState()
        {
            // Snapshot peer IDs (excluding local user)
            var peerIds = _viewModel.Users
                .Where(u => u.UID != _viewModel.LocalUser.UID)
                .Select(u => u.UID)
                .ToList();

            bool isEncryptionReady;

            if (!Settings.Default.UseEncryption)
            {
                // Encryption disabled globally
                isEncryptionReady = false;
            }
            else if (peerIds.Count == 0)
            {
                // Solo mode: nothing to sync, ready by definition
                isEncryptionReady = true;
            }
            else
            {
                // Multi-client: all peers must have a known public key
                lock (_viewModel.KnownPublicKeys)
                {
                    isEncryptionReady = peerIds.All(uid => _viewModel.KnownPublicKeys.ContainsKey(uid));
                }
            }

            // Update UI flags atomically on the UI thread
            _uiDispatcherInvoke(() =>
            {
                IsEncryptionReady = isEncryptionReady;
            });

            ClientLogger.Log($"EvaluateEncryptionState called — Ready={isEncryptionReady}", ClientLogLevel.Debug);
            ClientLogger.Log($"EvaluateEncryptionState: UseEncryption={Settings.Default.UseEncryption}, Peers={peerIds.Count}, Ready={isEncryptionReady}", ClientLogLevel.Info);

            return isEncryptionReady;
        }

        /// <summary>
        /// • Publish the local public key once per session.
        /// • Synchronize peer keys (handles solo short-circuit internally).
        /// • Validate readiness and update UI state.
        /// </summary>
        /// <return>Returns true if encryption is enabled and peers are fully ready (or solo is detected).</return>
        public async Task<bool> InitializeEncryptionAsync(CancellationToken cancellationToken)
        {
            if (!_localKeyPublished)
            {
                if (_viewModel.LocalUser?.PublicKeyDer != null && _viewModel.LocalUser.PublicKeyDer.Length > 0)
                {
                    // Publishes the local public key; server redistributes to peers who need it.
                    await _server.SendPublicKeyToServerAsync(
                        _viewModel.LocalUser.UID,
                        _viewModel.LocalUser.PublicKeyDer,
                        cancellationToken
                    );

                    _localKeyPublished = true;
                    ClientLogger.Log("InitializeEncryptionAsync: local public key published.", ClientLogLevel.Debug);
                }
                else
                {
                    ClientLogger.Log("InitializeEncryptionAsync: local public key not yet available, skipping publish.",
                        ClientLogLevel.Warn);
                }
            }

            // Synchronizes peer keys
            bool syncOk = await SyncKeysAsync(cancellationToken);

            // Evaluates final state for consistency and updates UI flags
            bool finaleStateofEncryption = EvaluateEncryptionState();

            ClientLogger.Log($"InitializeEncryptionAsync completed — SyncOk={syncOk}, Ready={finaleStateofEncryption}", ClientLogLevel.Info);

            return syncOk && finaleStateofEncryption;
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
                    await _server.SendRequestToPeerForPublicKeyAsync(uid, cancellationToken);
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

