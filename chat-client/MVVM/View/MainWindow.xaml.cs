/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.3</version>
/// <date>June 17th, 2024</date>

using chat_client.MVVM.ViewModel;
using chat_client.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;


namespace chat_client
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private void cmdConnect_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(MainViewModel.Username))
            {
                try
                {
                    cmdConnect.IsEnabled = false;
                    txtUsername.IsEnabled = false;
                    MainViewModel._server.ConnectToServer(MainViewModel.Username);
                    this.Title += " - Connecté au serveur.";
                    MainViewModel.IsConnectedToServer = true;
                    spnCenter.Visibility = Visibility.Visible;
                }

                catch (Exception ex)
                {
                    MessageBox.Show("Le serveur est injoignable ou il a refusé la connexion.", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                    cmdConnect.IsEnabled = true;
                    txtUsername.IsEnabled = true;
                }
            }
        }

        private void cmdSend_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(MainViewModel.Message))
            {
                MainViewModel._server.SendMessageToServer(MainViewModel.Message);
                txtMessageToSend.Text = "";
                txtMessageToSend.Focus();
            }
        }

        private void OnTextBoxTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (sender is TextBox txtbox)
            {
                if (string.IsNullOrEmpty(txtbox.Text))
                {
                    txtbox.Background = (ImageBrush)FindResource("txtUsername_background");
                }
                else
                {
                    txtbox.Background = null;
                }
            }
        }

        private void txtMessageToSend_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (txtMessageToSend.Text == "")
            {
                cmdSend.IsEnabled = false;
            }
            else
            {
                cmdSend.IsEnabled = true;
            }
        }

    }
}