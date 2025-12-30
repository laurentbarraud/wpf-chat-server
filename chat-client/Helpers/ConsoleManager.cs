/// <file>ConsoleManager.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>December 30th, 2025</date>

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace chat_client.Helpers
{
    public static class ConsoleManager
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeConsole();

        private const int ATTACH_PARENT_PROCESS = -1;

        /// <summary>
        /// Opens or attaches a console window and hooks up standard I/O.
        /// </summary>
        public static void Show()
        {
            // Try to connect to the parent console, else make a new one
            if (!AttachConsole(ATTACH_PARENT_PROCESS))
                AllocConsole();

            // Send all Console.Write/WriteLine to this window
            var outWriter = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
            Console.SetOut(outWriter);
            Console.SetError(outWriter);

            // Read Console.ReadLine from this window
            Console.SetIn(new StreamReader(Console.OpenStandardInput()));

            ClientLogger.Log("[Console] Debug console activated.", ClientLogLevel.Info);
        }

        /// <summary>
        /// Closes the console window if one was opened.
        /// </summary>
        public static void Hide()
        {
            FreeConsole();
        }
    }
}


