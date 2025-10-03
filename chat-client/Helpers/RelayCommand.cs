/// <file>RelayCommand.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>October 4th, 2025</date>

using System;
using System.Windows.Input;

namespace chat_client.Helpers
{
    /// <summary>
    /// Provides a simple command that runs an Action when called
    /// and checks a Func<bool> to see if it can run.
    /// This class is used in MainViewModel to bind buttons or menu items in XAML.
    /// </summary>
    public class RelayCommand : ICommand
    {
        // Holds the method to run when the command executes.
        private readonly Action _execute;

        // Holds the method to check if the command can run.
        private readonly Func<bool> _canExecute;

        /// <summary>
        /// Occurs when WPF asks to recheck whether the command can run.
        /// </summary>
        public event EventHandler? CanExecuteChanged;

        /// <summary>
        /// Creates a RelayCommand.
        /// </summary>
        /// <param name="execute">
        /// The Action to run when Execute is called.
        /// </param>
        /// <param name="canExecute">
        /// The Func<bool> to run when CanExecute is called.
        /// If null, the command stays enabled always.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// Thrown if the execute Action is null.
        /// </exception>
        public RelayCommand(Action execute, Func<bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute ?? (() => true);
        }

        /// <summary>
        /// Returns true if the command is allowed to run.
        /// </summary>
        /// <param name="parameter">
        /// Not used here.
        /// </param>
        public bool CanExecute(object? parameter)
        {
            return _canExecute();
        }

        /// <summary>
        /// Runs the stored Action.
        /// </summary>
        /// <param name="parameter">
        /// Not used here.
        /// </param>
        public void Execute(object? parameter)
        {
            _execute();
        }

        /// <summary>
        /// Tells WPF to recheck CanExecute and update bound controls.
        /// </summary>
        public void RaiseCanExecuteChanged()
        {
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        }
    }
}

