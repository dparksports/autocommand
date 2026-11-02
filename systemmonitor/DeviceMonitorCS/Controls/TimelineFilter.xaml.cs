using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;

namespace DeviceMonitorCS.Controls
{
    public partial class TimelineFilter : UserControl
    {
        public event Action FiltersChanged;

        public TimelineFilter()
        {
            InitializeComponent();
        }

        public List<string> GetSelectedCategories()
        {
            var list = new List<string>();
            foreach (var child in (this.Content as StackPanel).Children)
            {
                if (child is CheckBox cb && cb.IsChecked == true && cb.Tag != null)
                {
                    list.Add(cb.Tag.ToString());
                }
            }
            return list;
        }

        private void Filter_Click(object sender, RoutedEventArgs e)
        {
            FiltersChanged?.Invoke();
        }
    }
}
