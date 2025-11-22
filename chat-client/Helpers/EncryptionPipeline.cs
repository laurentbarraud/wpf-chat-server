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
    internal class EncryptionPipeline
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
        /// Determines whether encryption is ready and logs the result.
        /// </summary>
        /// <returns>True if encryption is enabled and all peer public keys are received; otherwise false.</returns>
        public bool EvaluateEncryptionState()
        {
            bool ready = Settings.Default.UseEncryption && AreAllKeysReceived();
            ClientLogger.Log($"EvaluateEncryptionState called — Ready: {ready}", ClientLogLevel.Debug);
            // Logs encryption readiness with settings snapshot
            ClientLogger.Log($"EvaluateEncryptionState: UseEncryption={Settings.Default.UseEncryption}, Ready={ready}", ClientLogLevel.Info);
            return ready;
        }

        /// <summary>
        /// Performs encryption initialization:
        /// - Publish the local public key (once).
        /// - Synchronize peer keys.
        /// - Validate readiness.
        /// Always proceeds to synchronization; returns true if peers are fully ready.
        /// </summary>
        public async Task<bool> InitializeEncryptionAsync(CancellationToken cancellationToken)
        {
            if (!_localKeyPublished)
            {
                // Publishes the local public key; server redistributes to peers who need it.
                if (_viewModel.LocalUser?.PublicKeyDer != null && _viewModel.LocalUser.PublicKeyDer.Length > 0)
                {
                    await _server.SendPublicKeyToServerAsync(_viewModel.LocalUser.UID,
                        _viewModel.LocalUser.PublicKeyDer, cancellationToken);

                    _localKeyPublished = true;
                }
                else
                {
                    ClientLogger.Log("InitializeAsync: Local public key not yet available, skipping publish.",
                        ClientLogLevel.Warn);
                }
            }

            // Always continue with key synchronization
            return await SyncKeysAsync(cancellationToken);
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
        /// Synchronizes the local public key with each connected peer.
        /// Requests missing peer keys sequentially and awaits each send.
        /// Returns true only when KnownPublicKeys is complete and valid.
        /// </summary>
        public async Task<bool> SyncKeysAsync(CancellationToken cancellationToken)
        {
            // Exits if encryption is disabled
            if (!Settings.Default.UseEncryption)
            {
                IsEncryptionReady = false;
                IsSyncingKeys = false;
                return false;
            }

            // Marks syncing state (UI notification is done by ViewModel)
            _uiDispatcherInvoke(() =>
            {
                IsSyncingKeys = true;
                IsEncryptionReady = false;
            });

            try
            {
                // Snapshot of peer UIDs (excluding local)
                var lstPeerIds = _viewModel.Users
                    .Where(u => u.UID != _viewModel.LocalUser.UID)
                    .Select(u => u.UID)
                    .ToList();

                // Solo mode: ready immediately
                if (lstPeerIds.Count == 0)
                {
                    IsEncryptionReady = true;
                    return true;
                }

                // Identifies missing keys
                List<Guid> missingKeys;
                lock (KnownPublicKeys)
                {
                    missingKeys = lstPeerIds
                        .Where(uid => !_viewModel.KnownPublicKeys.ContainsKey(uid))
                        .ToList();
                }

                ClientLogger.Log($"SyncKeysAsync: peers={lstPeerIds.Count}, missingKeys={missingKeys.Count}",
                    ClientLogLevel.Debug
                );

                // Requests each missing peer key sequentially
                foreach (var uid in missingKeys)
                {
                    await  _server.SendRequestToPeerForPublicKeyAsync(uid, cancellationToken);
                }

                IsEncryptionReady = (missingKeys.Count == 0);
                
                return IsEncryptionReady;
            }
            catch (OperationCanceledException)
            {
                // Preserve cancellation semantics
                throw;
            }
            catch (Exception ex)
            {
                ClientLogger.Log($"SyncKeys failed: {ex.Message}", ClientLogLevel.Error);
                return false;
            }
            finally
            {
                // Always reset syncing flag
                _uiDispatcherInvoke(() =>
                {
                    IsSyncingKeys = false;
                });
            }
        }
    }
}

