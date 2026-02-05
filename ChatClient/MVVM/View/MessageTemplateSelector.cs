/// <file>MessageTemplateSelector.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 5th, 2026</date>

using ChatClient.MVVM.Model;
using ChatClient.MVVM.ViewModel;
using System.Windows;
using System.Windows.Controls;

namespace ChatClient.MVVM.View
{
    public class MessageTemplateSelector : DataTemplateSelector
    {
        public DataTemplate RawTextTemplate { get; set; } = null!;
        public DataTemplate SentMessageTemplate { get; set; } = null!;
        public DataTemplate ReceivedMessageTemplate { get; set; } = null!;
        public DataTemplate SystemMessageTemplate { get; set; } = null!;

        public override DataTemplate SelectTemplate(object item, DependencyObject container)
        {
            if (item is not ChatMessage chatMessage)
            {
                return base.SelectTemplate(item, container);
            }

            // Gets the viewmodel from the datacontext of the container
            if (container is FrameworkElement frameworkElement && frameworkElement.DataContext is MainViewModel viewModel &&
                viewModel.RawTextMode)
            {
                return RawTextTemplate;
            }

            if (chatMessage.IsSystemMessage) 
            { 
                return SystemMessageTemplate;
            }

            if (chatMessage.IsFromLocalUser)
            {
                return SentMessageTemplate;
            }

            return ReceivedMessageTemplate;
        }
    }
}
