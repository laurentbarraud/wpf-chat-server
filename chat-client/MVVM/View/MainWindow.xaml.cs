/// <file>MainWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>0.3</version>
/// <date>June 17th, 2024</date>

using chat_client.MVVM.ViewModel;
using chat_client.Net;
using System.Windows;


namespace chat_client
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private void cmdConnectDisconnect_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(MainViewModel.Username))
            {
                try
                {
                    MainViewModel._server.ConnectToServer(MainViewModel.Username);
                    this.Title += " - Connecté au serveur.";
                }

                catch (Exception ex)
                {
                    MessageBox.Show("Le serveur est injoignable ou il a refusé la connexion.", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void cmdSend_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(MainViewModel.Message))
            {
                MainViewModel._server.SendMessageToServer(MainViewModel.Message);
            }
        }
    }
}