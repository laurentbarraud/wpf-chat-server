/// <file>ConsoleManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>September 22th, 2025</date>

using System;
using System.Runtime.InteropServices;

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides access to the system console window for debug output.
    /// Used to display logs when --debug or -d is specified at startup.
    /// </summary>
    public static class ConsoleManager
    {
        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        /// <summary>
        /// Shows the system console window and enables standard output.
        /// </summary>
        public static void Show()
        {
            AllocConsole();
            Console.WriteLine("[Console] Debug console activated.");
        }
    }
}
