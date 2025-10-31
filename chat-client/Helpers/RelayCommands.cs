/// <file>RelayCommand.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 31th, 2025</date>

using System;                               
using System.Windows.Input;                // Imports ICommand and CommandManager.

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides a command that runs an action with a parameter of type T.
    /// Stores an execute callback and an optional can-execute check.
    /// </summary>
    public class RelayCommands<T> : ICommand
    {
        // Stores the action to invoke when the command executes.
        private readonly Action<T> _execute;
        // Stores the function to check if the command can execute.
        private readonly Predicate<T> _canExecute;

        /// <summary>
        /// Occurs when WPF requests to re-evaluate CanExecute.
        /// </summary>
        event EventHandler? ICommand.CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;   // Subscribes to WPF requery event.
            remove => CommandManager.RequerySuggested -= value;   // Unsubscribes from WPF requery event.
        }

        /// <summary>
        /// Initializes a new instance of RelayCommand.
        /// </summary>
        /// <param name="execute">Action to invoke on Execute call.</param>
        /// <param name="canExecute">Predicate to invoke on CanExecute check; default returns true.</param>
        public RelayCommands(Action<T> execute, Predicate<T>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));               // Assigns execute or throws if null.
            _canExecute = canExecute ?? (_ => true);                                              // Assigns canExecute or default that always returns true.
        }

        /// <summary>
        /// Determines whether the command can execute with the given parameter.
        /// </summary>
        /// <param name="parameter">Parameter passed from UI; cast to T.</param>
        /// <returns>True if _canExecute returns true; otherwise false.</returns>
        public bool CanExecute(object? parameter) =>
            _canExecute((T)parameter!);         // Invokes the canExecute predicate with the casted parameter.

        /// <summary>
        /// Executes the command action with the given parameter.
        /// </summary>
        /// <param name="parameter">Parameter passed from UI; cast to T.</param>
        public void Execute(object? parameter) =>
            _execute((T)parameter!);            // Invokes the execute action with the casted parameter.

        /// <summary>
        /// Forces WPF to re-evaluate CanExecute and refresh bound controls.
        /// </summary>
        public void RaiseCanExecuteChanged()
        {
            CommandManager.InvalidateRequerySuggested();
        }
    }

    /// <summary>
    /// Provides a simple command that runs an action without a parameter.
    /// Stores an execute callback and an optional can-execute check.
    /// </summary>
    public class RelayCommand : ICommand
    {
        // Stores the action to invoke when the command executes.
        private readonly Action _execute;
        // Stores the function to check if the command can execute.
        private readonly Func<bool> _canExecute;

        /// <summary>
        /// Occurs when WPF requests to re-evaluate CanExecute.
        /// </summary>
        event EventHandler? ICommand.CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;   // Subscribes to WPF requery event.
            remove => CommandManager.RequerySuggested -= value;   // Unsubscribes from WPF requery event.
        }

        /// <summary>
        /// Initializes a new instance of RelayCommand.
        /// </summary>
        /// <param name="execute">Action to invoke on Execute call.</param>
        /// <param name="canExecute">Function to invoke on CanExecute check; default returns true.</param>
        public RelayCommand(Action execute, Func<bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));               // Assigns execute or throws if null.
            _canExecute = canExecute ?? (() => true);                                             // Assigns canExecute or default that always returns true.
        }

        /// <summary>
        /// Determines whether the command can execute.
        /// </summary>
        /// <param name="parameter">Not used; always invokes _canExecute.</param>
        /// <returns>True if _canExecute returns true; otherwise false.</returns>
        public bool CanExecute(object? parameter) =>
            _canExecute();                     // Invokes the canExecute function.

        /// <summary>
        /// Executes the command action.
        /// </summary>
        /// <param name="parameter">Not used; always invokes _execute.</param>
        public void Execute(object? parameter) =>
            _execute();                        // Invokes the execute action.

        /// <summary>
        /// Forces WPF to re-evaluate CanExecute and refresh bound controls.
        /// </summary>
        public void RaiseCanExecuteChanged()
        {
            CommandManager.InvalidateRequerySuggested();
        }
    }
}


