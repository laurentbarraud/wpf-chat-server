/// <file>AboutWindow.xaml.cs</file>
/// <author>Laurent Barraud</author>
/// <version>1.0</version>
/// <date>January 20th, 2026</date>

using ChatClient.Helpers;
using ChatClient.MVVM.ViewModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace ChatClient.MVVM.View
{
    public partial class AboutWindow : Window
    {
        // PRIVATE FIELDS

        /// <summary> 
        /// Indicates whether the storm animation is currently active.
        /// Prevents multiple overlapping animations from being triggered.
        /// </summary>
        private bool _stormRunning = false;

        // Duration of effect in milliseconds
        const int STORM_DURATION_MS = 5000;

        private readonly AboutViewModel _aboutViewModel;

        public AboutWindow()
        {
            InitializeComponent();

            _aboutViewModel = new AboutViewModel(); 
            DataContext = _aboutViewModel;
            Title = _aboutViewModel.AboutWindowTitle;
        }

        private void AnimateFlake(Ellipse flake, Random rnd)
        {
            double endY = AtmosphericCanvas.ActualHeight + 40;
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
            sb.Completed += (_, __) => { AtmosphericCanvas.Children.Remove(flake); };
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
        private void CoverUpAppTitle()
        {
            AppTitle.Foreground = new SolidColorBrush(Color.FromRgb(40, 60, 90));
        }

        /// <summary>
        /// Restores the original daylight gradient after the temporary
        /// night‑fade effect completes.
        /// </summary>
        private void FadeBackgroundToDay()
        {
            // Easing curve for a symmetrical, natural return.
            var easing = new CubicEase { EasingMode = EasingMode.EaseOut };

            // Original gradient colors
            var dayLight = (Color)ColorConverter.ConvertFromString("#F9F9FF");
            var dayMid = (Color)ColorConverter.ConvertFromString("#001F44");
            var dayDark = Colors.Black;

            // Animate each gradient stop back to its initial color.
            GS_Light.BeginAnimation(GradientStop.ColorProperty,
                new ColorAnimation(dayLight, TimeSpan.FromMilliseconds(1500))
                {
                    EasingFunction = easing
                });

            GS_Mid.BeginAnimation(GradientStop.ColorProperty,
                new ColorAnimation(dayMid, TimeSpan.FromMilliseconds(1500))
                {
                    EasingFunction = easing
                });

            GS_Dark.BeginAnimation(GradientStop.ColorProperty,
                new ColorAnimation(dayDark, TimeSpan.FromMilliseconds(1500))
                {
                    EasingFunction = easing
                });
        }


        /// <summary>
        /// Gradually darkens the background gradient to night‑tinted colors.
        /// </summary>
        private async Task FadeBackgroundToNightAsync()
        {
            // A gentle easing curve for a natural, cinematic fade.
            var easing = new CubicEase { EasingMode = EasingMode.EaseOut };

            var nightLight = Color.FromRgb(40, 60, 90);   // soft night blue
            var nightMid = Color.FromRgb(10, 30, 60);     // deeper night blue
            var nightDark = Color.FromRgb(0, 0, 0);       // black 

            // Animates each gradient stop toward its night variant.
            GS_Light.BeginAnimation(GradientStop.ColorProperty,
                new ColorAnimation(nightLight, TimeSpan.FromMilliseconds(700))
                {
                    EasingFunction = easing
                });

            GS_Mid.BeginAnimation(GradientStop.ColorProperty,
                new ColorAnimation(nightMid, TimeSpan.FromMilliseconds(700))
                {
                    EasingFunction = easing
                });

            GS_Dark.BeginAnimation(GradientStop.ColorProperty,
                new ColorAnimation(nightDark, TimeSpan.FromMilliseconds(700))
                {
                    EasingFunction = easing
                });

            // Waits for the effect to finish.
            await Task.Delay(STORM_DURATION_MS + 2500);

            // Restores the original gradient for background.
            FadeBackgroundToDay();
        }


        /// <summary>
        /// Gradually fades the hotspot’s background back to transparent,
        /// ensuring the brush is unfrozen before animating.
        /// </summary>
        private void FadeOutHotspot()
        {
            // Ignores fade-out if the hotspot is already transparent.
            if (HotspotButton.Background is not SolidColorBrush currentBrush)
            {
                return;
            }

            // Skips animation when the current color is already fully off.
            if (currentBrush.Color == Colors.Transparent)
            {
                return;
            }

            // Clones the brush when needed to avoid frozen instances from templates.
            var bgBrush = currentBrush.IsFrozen ? currentBrush.Clone() : currentBrush;
            HotspotButton.Background = bgBrush;

            // Defines a transition from the current tint back to transparent.
            var colorAnim = new ColorAnimation
            {
                From = bgBrush.Color,                 // Always start from the actual color.
                To = Colors.Transparent,              // Fade back to invisible.
                Duration = TimeSpan.FromMilliseconds(600),
                FillBehavior = FillBehavior.Stop
            };

            // Ensures the hotspot ends fully transparent once the fade completes.
            colorAnim.Completed += (_, __) =>
            {
                HotspotButton.Background = new SolidColorBrush(Colors.Transparent);
            };

            // Animates the brush’s Color property using the defined animation.
            bgBrush.BeginAnimation(SolidColorBrush.ColorProperty, colorAnim);
        }

        /// <summary>
        /// Briefly awakens the hotspot’s hidden glow.
        /// </summary>
        public void HighlightHotspotButton()
        {
            // Defines a color transition from transparent to the highlight tint
            var colorAnim = new ColorAnimation
            {
                From = Colors.Transparent,
                To = Color.FromRgb(180, 240, 240),
                Duration = TimeSpan.FromMilliseconds(250),
                FillBehavior = FillBehavior.HoldEnd
            };

            // Always start from a fresh, unfrozen brush to avoid template/resource issues.
            var brush = new SolidColorBrush(Colors.Transparent);

            HotspotButton.Background = brush;

            // Animates the brush’s Color property using the defined animation.
            brush.BeginAnimation(SolidColorBrush.ColorProperty, colorAnim);
        }

        /// <summary>
        /// Confirms a season shift with a soft, sun‑tinted bloom.
        /// </summary>
        public void HighlightSummerOnHotspotButton()
        {
            // A fresh brush is created for this transient effect.
            // Using a new instance avoids any frozen-resource pitfalls
            // and guarantees that the animation pipeline has full control.
            var colorBrush = new SolidColorBrush(Colors.Transparent);

            // The hotspot’s background is temporarily replaced with this brush.
            HotspotButton.Background = colorBrush;

            var sunColor = Color.FromRgb(245, 242, 109);

            // A cubic easing curve gives the bloom a gentle, organic rise.
            var easing = new CubicEase
            {
                EasingMode = EasingMode.EaseOut
            };

            // A smooth rise from transparent to the sun tint.
            var flashAnim = new ColorAnimation
            {
                From = Colors.Transparent,
                To = sunColor,
                Duration = TimeSpan.FromMilliseconds(1000),
                EasingFunction = easing,
                FillBehavior = FillBehavior.Stop
            };

            // Animation is applied to the brush’s Color property.
            colorBrush.BeginAnimation(SolidColorBrush.ColorProperty, flashAnim);
        }

        /// <summary>
        /// A click on the right spot will trigger a special feature.
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void HotspotButton_Click(object sender, RoutedEventArgs e)
        {
            _aboutViewModel.IsNightMode = true;

            HighlightHotspotButton();
            CoverUpAppTitle();
            _ = FadeBackgroundToNightAsync();
            StartStorm();
        }

        /// <summary>
        /// Brushing the name awakens the hidden glow but only the first time.
        /// </summary>
        private void LicenceFinalLabel_MouseEnter(object sender, MouseEventArgs e)
        {
            if (Properties.Settings.Default.WinterHasFallen || _aboutViewModel.HotSpotHintShown) 
            { 
                return; 
            }

            else 
            {
                _aboutViewModel.HotSpotHintShown = true;
                HighlightHotspotButton();
            }
        }

        /// <summary>
        /// Fades the hotspot when focus leaves the label, unless the effect has already been consumed.
        /// </summary>
        private void LicenceFinalLabel_MouseLeave(object sender, MouseEventArgs e)
        {
            if (_stormRunning) 
            {
                return; 
            } 

            else
            {
                FadeOutHotspot();
            }
        }

        private void ResetAppTitle()
        { 
            AppTitle.Foreground = Brushes.Black; 
        }

        /// <summary> Listens for the quiet gesture that restores what once shifted. </summary>
        private void ResetButton_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {           
            if (_stormRunning)
            {
                return;
            }

            if (Properties.Settings.Default.WinterHasFallen)
            {
                Properties.Settings.Default.WinterHasFallen = false;
                Properties.Settings.Default.Save();

                ClientLogger.Log("WinterHasFallen app parameter reset. Awaiting the next explorer.", ClientLogLevel.Info);
                HighlightSummerOnHotspotButton();
            }
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
        /// Summons an ephemeral disturbance in the interface. 
        /// </summary>
       private async void StartStorm()
        {
            if (_stormRunning)
            {
                return;
            }

            _stormRunning = true;

            // Only records the event the first time it ever happens.
            if (!Properties.Settings.Default.WinterHasFallen)
            { 
                Properties.Settings.Default.WinterHasFallen = true; 
                Properties.Settings.Default.Save(); 
            } 

            var rnd = new Random();
            var flakeList = new List<Ellipse>();

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            // Stopwatch is the right tool for a short, smooth and deterministic visual effect.
            // WPF Storyboards are already paced by the UI thread; using a Timer would cause
            // irregular spawns and potential dispatcher collisions.

            // Main loop: generate flakes for the duration of the storm
            while (stopwatch.ElapsedMilliseconds < STORM_DURATION_MS)
            {
                // Creates a new flake
                var flake = new Ellipse
                {
                    Width = rnd.Next(3, 8),
                    Height = rnd.Next(3, 8),
                    Fill = Brushes.White,
                    Opacity = rnd.NextDouble() * 0.8 + 0.2
                };

                // Starting position: random X at top
                double startPosX = rnd.NextDouble() * AtmosphericCanvas.ActualWidth;
                double startPosY = -20; Canvas.SetLeft(flake, startPosX);

                // Positions the flake at its initial vertical coordinate
                Canvas.SetTop(flake, startPosY);
                
                AtmosphericCanvas.Children.Add(flake);
                flakeList.Add(flake);

                // Animates the flake
                AnimateFlake(flake, rnd);

                // Spawn rate
                await Task.Delay(rnd.Next(40, 120));

            } // Waits a bit for remaining flakes to finish falling
            await Task.Delay(2000);

            // Cleanup
            foreach (var flake in flakeList)
            {
                AtmosphericCanvas.Children.Remove(flake);
            }

            _stormRunning = false;
          
            FadeOutHotspot();
            ResetAppTitle();
        }

        /// <summary>
        /// Triggers the legacy pathway once used by early builds
        /// and quietly maintained.
        /// </summary>
        public void TriggerHotSpot()
        {
            // WPF equivalent of a WinForms PerformClick()
            HotspotButton.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
        }
    }
}
