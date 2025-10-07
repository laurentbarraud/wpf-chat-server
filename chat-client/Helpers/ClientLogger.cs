/// <file>ClientLogger.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 7th, 2025</date>

namespace chat_client.Helpers
{
    /// <summary>
    /// Defines severity levels for client-side logging.
    /// </summary>
    public enum ClientLogLevel
    {
        Info,
        Debug,
        Warn,
        Error
    }

    /// <summary>
    /// Provides static methods to log messages with timestamps and severity prefixes.
    /// Supports raw and localized logging without crashing the client.
    /// </summary>
    public static class ClientLogger
    {
        /// <summary>
        /// When true, allows debug-level messages to be written to the console.
        /// Default is false to suppress verbose output in production.
        /// </summary>
        public static bool IsDebugEnabled { get; set; } = false;

        /// <summary>
        /// Writes a formatted message to the console with a timestamp and severity prefix.
        /// Debug messages are skipped unless <see cref="IsDebugEnabled"/> is true.
        /// </summary>
        /// <param name="message">The raw text to log.</param>
        /// <param name="level">
        /// The severity level of the log entry.
        /// Defaults to <see cref="ClientLogLevel.Info"/>.
        /// </param>
        public static void Log(string message, ClientLogLevel level = ClientLogLevel.Info)
        {
            if (level == ClientLogLevel.Debug && !IsDebugEnabled)
                return;

            string prefix = level switch
            {
                ClientLogLevel.Info => "[INFO]  ",
                ClientLogLevel.Warn => "[WARN]  ",
                ClientLogLevel.Error => "[ERROR] ",
                ClientLogLevel.Debug => "[DEBUG] ",
                _ => "[DEBUG] "
            };

            string timestamp = DateTime.Now.ToString("dd.MM.yyyy HH:mm:ss");
            Console.WriteLine($"{prefix}[{timestamp}] {message}");
        }

        /// <summary>
        /// Retrieves a localized string by key and logs it with the specified severity.
        /// </summary>
        /// <param name="resourceKey">The key identifying the localized resource.</param>
        /// <param name="level">
        /// The severity level of the log entry.
        /// Defaults to <see cref="ClientLogLevel.Info"/>.
        /// </param>
        public static void LogLocalized(string resourceKey, ClientLogLevel level = ClientLogLevel.Info)
        {
            string message = LocalizationManager.GetString(resourceKey);
            Log(message, level);
        }
    }
}


