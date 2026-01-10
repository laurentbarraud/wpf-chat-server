/// <file>ClientLogger.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 10th, 2026</date>

namespace ChatClient.Helpers
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
        /// Logs a localized message using a resource key and up to two optional string arguments.
        /// Retrieves the corresponding template from the LocalizationManager and formats it with the provided values.
        /// Falls back to the key itself if no template is found.
        /// </summary>
        /// <param name="messageKey">The localization key identifying the message template.</param>
        /// <param name="level">The severity level to apply to the log entry.</param>
        /// <param name="arg1">Optional first argument to inject into the template.</param>
        /// <param name="arg2">Optional second argument to inject into the template.</param>
        public static void LogLocalized(string messageKey, ClientLogLevel level, string? arg1 = null, string? arg2 = null)
        {
            var template = LocalizationManager.GetString(messageKey) ?? messageKey;
            var message = string.Format(template, arg1 ?? "", arg2 ?? "");
            Log(message, level);
        }
    }
}


