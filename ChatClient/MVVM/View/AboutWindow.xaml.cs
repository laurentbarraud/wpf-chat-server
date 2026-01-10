/// <file>AboutWindow.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 10th, 2026</date>

using ChatClient.Converters;
using ChatClient.Helpers;
using ChatClient.MVVM.ViewModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Xml.Linq;

namespace ChatClient.MVVM.View
{
    public partial class AboutWindow : Window
    {
        // PRIVATE FIELDS

        /// <summary> 
        /// Indicates whether the snowstorm animation is currently active.
        /// Prevents multiple overlapping animations from being triggered.
        /// </summary>
        private bool _snowstormRunning = false;

        public AboutWindow()
        {
            InitializeComponent();
            DataContext = new AboutViewModel();
        }

        private void AnimateSnowflake(Ellipse flake, Random rnd)
        {
            double endY = SnowCanvas.ActualHeight + 40;
            double driftX = rnd.NextDouble() * 100 - 50;

            // left/right drift
            var sb = new Storyboard();

            // Vertical fall
            var animY = new DoubleAnimation
            {
                From = Canvas.GetTop(flake),
                To = endY,
                Duration = TimeSpan.FromSeconds(rnd.NextDouble() * 2 + 2),
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn }
            };

            Storyboard.SetTarget(animY, flake);
            Storyboard.SetTargetProperty(animY, new PropertyPath("(Canvas.Top)"));
            sb.Children.Add(animY);

            // Horizontal drift
            var animX = new DoubleAnimation
            {
                From = Canvas.GetLeft(flake),
                To = Canvas.GetLeft(flake) + driftX,
                Duration = animY.Duration,
                EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
            };

            Storyboard.SetTarget(animX, flake);
            Storyboard.SetTargetProperty(animX, new PropertyPath("(Canvas.Left)"));
            sb.Children.Add(animX);

            // Auto-remove when animation ends
            sb.Completed += (_, __) => { SnowCanvas.Children.Remove(flake); };
            sb.Begin();
        }


        /// <summary>
        /// Handles click on the CLI arguments textblock and displays the help MessageBox.
        /// </summary>
        private void CliTextBlock_MouseDown(object sender, MouseButtonEventArgs e)
        {
            ShowCommandLineArgumentsHelp();
        }

        /// <summary>
        /// Closes the About window when the OK button is clicked.
        /// Used in CLI mode to terminate the application after displaying version info.
        /// </summary>
        private void CmdOk_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        /// <summary> 
        /// Gradually fades the hotspot’s background back to transparent once the snow 
        /// animation has finished, restoring its idle appearance.
        /// </summary>
        private void FadeOutHotspot() 
        { 
            var anim = new ColorAnimation { 
                From = Color.FromRgb(180, 240, 240), To = Colors.Transparent, 
                Duration = TimeSpan.FromMilliseconds(600), FillBehavior = FillBehavior.Stop 
            }; 
            
            var bgBrush = ServerHotspotButton.Background as SolidColorBrush; 
            
            if (bgBrush == null) 
            { 
                bgBrush = new SolidColorBrush(Color.FromRgb(180, 240, 240)); 
                ServerHotspotButton.Background = bgBrush; 
            } 
            
            anim.Completed += (_, __) => ServerHotspotButton.Background = new SolidColorBrush(Colors.Transparent); 
            bgBrush.BeginAnimation(SolidColorBrush.ColorProperty, anim); 
        }

        /// <summary> 
        /// Animates the hotspot by fading its background from transparent to a light blue 
        /// to visually indicate that the snow effect has been triggered. 
        /// </summary>
        private void HighlightServerHotspotButton() 
        { 
            var anim = new ColorAnimation { 
                From = Colors.Transparent, To = Color.FromRgb(180, 240, 240),
                Duration = TimeSpan.FromMilliseconds(250), FillBehavior = FillBehavior.HoldEnd 
            }; 
        
            var brush = new SolidColorBrush(Colors.Transparent); 
            ServerHotspotButton.Background = brush; 
            brush.BeginAnimation(SolidColorBrush.ColorProperty, anim); 
        }

        /// <summary>
        /// Brushing the name awakens the hidden glow.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void LicenceFinalLabel_MouseEnter(object sender, MouseEventArgs e)
        {  
            HighlightServerHotspotButton(); 
        }

        /// <summary>
        /// When attention drifts away, the light fades… unless the storm is already alive.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void LicenceFinalLabel_MouseLeave(object sender, MouseEventArgs e)
        { 
            if (!_snowstormRunning) 
            { 
                FadeOutHotspot(); 
            } 
        }
        /// <summary>
        /// A click on the right spot will trigger a special feature.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ServerHotspotButton_Click(object sender, RoutedEventArgs e)
        {
            HighlightServerHotspotButton();
            StartSnowstorm();
        }

        /// <summary>
        /// Shows a localized MessageBox listing all supported CLI arguments.
        /// If this window was never shown (IsVisible==false), the app closes.
        /// Otherwise, the help box is just closed.
        /// </summary>
        public void ShowCommandLineArgumentsHelp()
        {
            // Retrieves raw help text and title from resources
            string rawCliOptionsHelpText = LocalizationManager.GetString("CliOptionsHelpText")
                             ?? "[[CliOptionsHelpText]]";
            string titleCliOptions = LocalizationManager.GetString("CliOptionsHelpTitle")
                             ?? "[[CliOptionsHelpTitle]]";

            // Converts escaped sequences to real line breaks and tabs
            string formattedCliOptionsHelpText = rawCliOptionsHelpText
                .Replace("\\n", "\n")
                .Replace("\\t", "\t");

            // Shows the styled MessageBox
            MessageBox.Show(
                formattedCliOptionsHelpText,
                titleCliOptions,
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            // If the AboutWindow was never shown, then exits the application
            if (!this.IsVisible)
                Application.Current.Shutdown();
        }

        /// <summary> 
        /// Launches a temporary animation.
        /// <summary> 
        private async void StartSnowstorm()
        {
            if (_snowstormRunning)
            {
                return;
            }

            _snowstormRunning = true;

            var rnd = new Random();
            var flakeList = new List<Ellipse>();

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            // Stopwatch is the right tool for a short, smooth and deterministic visual effect.
            // WPF Storyboards are already paced by the UI thread; using a Timer would cause
            // irregular spawns and potential dispatcher collisions.

            // Duration of the effect
            const int STORM_DURATION_MS = 10000;

            // Main loop: generate flakes for 10 seconds
            while (stopwatch.ElapsedMilliseconds < STORM_DURATION_MS)
            {
                // Creates a new snowflake
                var flake = new Ellipse
                {
                    Width = rnd.Next(3, 8),
                    Height = rnd.Next(3, 8),
                    Fill = Brushes.White,
                    Opacity = rnd.NextDouble() * 0.8 + 0.2
                };

                // Starting position: random X at top
                double startPosX = rnd.NextDouble() * SnowCanvas.ActualWidth;
                double startPosY = -20; Canvas.SetLeft(flake, startPosX);
                
                Canvas.SetTop(flake, startPosY);

                SnowCanvas.Children.Add(flake);
                flakeList.Add(flake);

                // Animates the flakes
                AnimateSnowflake(flake, rnd);

                // Spawn rate
                await Task.Delay(rnd.Next(40, 120));

            } // Waits a bit for remaining flakes to finish falling
            await Task.Delay(2000);

            // Cleanup
            foreach (var flake in flakeList)
            {
                SnowCanvas.Children.Remove(flake);
            }

            _snowstormRunning = false;
            
            FadeOutHotspot();
        }
    }
}
