/// <file>MessageTemplateSelector.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>February 6th, 2026</date>

using ChatClient.MVVM.Model;
using ChatClient.MVVM.ViewModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms;
using static System.Net.Mime.MediaTypeNames;

namespace ChatClient.MVVM.View
{
    public class MessageTemplateSelector : DataTemplateSelector
    {
        public DataTemplate RawTextTemplate { get; set; } = null!;
        public DataTemplate SentBubbleTemplate { get; set; } = null!;
        public DataTemplate ReceivedMessageTemplate { get; set; } = null!;
        public DataTemplate SystemMessageTemplate { get; set; } = null!;

        /// <summary>
        /// Selects the appropriate DataTemplate for a chat message based on its type
        /// and the current UI display mode. Prioritizes the raw-text mode when enabled,
        /// then falls back to system, sent, or received message templates.
        /// </summary>
        public override DataTemplate SelectTemplate(object item, DependencyObject container)
        {
            if (item is not ChatMessage chatMessage)
            {
                return base.SelectTemplate(item, container);
            }

            // Retrieves the MainViewModel from the owning ItemsControl
            if (container is FrameworkElement fe)
            {
                var itemsControl = ItemsControl.ItemsControlFromItemContainer(fe);
                if (itemsControl?.DataContext is MainViewModel viewModel && viewModel.RawTextMode)
                {
                    return RawTextTemplate;
                }
            }

            if (chatMessage.IsSystemMessage)
            {
                return SystemMessageTemplate;
            }

            if (chatMessage.IsFromLocalUser)
            {
                return SentBubbleTemplate;
            }

            return ReceivedMessageTemplate;
        }
    }
}
