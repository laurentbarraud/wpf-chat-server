/// <file>MessageTemplateSelector.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.1</version>
/// <date>July 10th, 2026</date>

using ChatClient.MVVM.Model;
using System.Windows;
using System.Windows.Controls;

namespace ChatClient.MVVM.View
{
    /// <summary>
    /// Presentation component: in the MVVM architecture, 
    /// everything related to presentation (XAML, styles, 
    /// converters, selectors, triggers, templates) must
    /// be stored in Views folder.
    /// </summary>
    public class MessageTemplateSelector : DataTemplateSelector
    {
        public DataTemplate RawTextTemplate { get; set; } = null!;
        public DataTemplate SentBubbleTemplate { get; set; } = null!;
        public DataTemplate ReceivedMessageTemplate { get; set; } = null!;
        public DataTemplate SystemMessageTemplate { get; set; } = null!;

        /// <summary>
        /// Selects the appropriate DataTemplate for a chat message based on its type
        /// and the current UI display mode. 
        /// </summary>
        public override DataTemplate SelectTemplate(object item, DependencyObject container)
        {
            // Ensures the item is a ChatMessage
            if (item is not ChatMessage chatMessage)
            {
                return base.SelectTemplate(item, container);
            }

            // Resolves ItemsControl to access MainViewModel
            if (container is FrameworkElement frameworkElement)
            {
                var itemsControl = ItemsControl.ItemsControlFromItemContainer(frameworkElement);

                // Raw text mode applies only in MainWindowLegacy
                if (Properties.Settings.Default.RawTextMode)
                {
                    if (Application.Current.MainWindow is ChatClient.MVVM.View.MainWindowLegacy)
                    {
                        return RawTextTemplate;
                    }
                }

            }

            // System messages
            if (chatMessage.IsSystemMessage)
            {
                return SystemMessageTemplate;
            }

            // Sent by local user
            if (chatMessage.IsFromLocalUser)
            {
                return SentBubbleTemplate;
            }

            // Received from peer
            return ReceivedMessageTemplate;
        }
    }
}