// PDFsharp - A .NET library for processing PDF
// See the LICENSE file in the solution root for more information.

using System;
using System.Collections;
using System.Text;
#if GDI
using System.Drawing;
using System.Windows.Forms;
#endif
using PdfSharp.Drawing;

#if GDI
namespace PdfSharp.Forms
{
    /// <summary>
    /// A combo box control for selection XColor values.
    /// </summary>
    public class ColorComboBox : ComboBox
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ColorComboBox"/> class.
        /// </summary>
        public ColorComboBox()
        {
            DropDownStyle = ComboBoxStyle.DropDownList;
            DrawMode = DrawMode.OwnerDrawFixed;
            Fill();
        }

        readonly XColorResourceManager _crm = new XColorResourceManager();

        /// <summary>
        /// Gets or sets the custom color.
        /// </summary>
        public XColor Color
        {
            get { return _color; }
            set
            {
                _color = value;
                if (value.IsKnownColor)
                {
                    XKnownColor color = XColorResourceManager.GetKnownColor(value.Argb);
                    for (int idx = 1; idx < Items.Count; idx++)
                    {
                        if (((ColorItem)Items[idx]).Color.Argb == value.Argb)
                        {
                            SelectedIndex = idx;
                            break;
                        }
                    }
                }
                else
                    SelectedIndex = 0;
                Invalidate();
            }
        }
        XColor _color = XColor.Empty;

        void Fill()
        {
            Items.Add(new ColorItem(XColor.Empty, "custom"));
            XKnownColor[] knownColors = XColorResourceManager.GetKnownColors(false);
            int count = knownColors.Length;
            for (int idx = 0; idx < knownColors.Length; idx++)
            {
                XKnownColor color = knownColors[idx];
                Items.Add(new ColorItem(XColor.FromKnownColor(color), _crm.ToColorName(color)));
            }
        }

        /// <summary>
        /// Keep control a drop down combo box.
        /// </summary>
        protected override void OnDropDownStyleChanged(EventArgs e)
        {
            DropDownStyle = ComboBoxStyle.DropDownList;
            base.OnDropDownStyleChanged(e);
        }

        /// <summary>
        /// Sets the color with the selected item.
        /// </summary>
        protected override void OnSelectedIndexChanged(EventArgs e)
        {
            int index = SelectedIndex;
            if (index > 0)
            {
                ColorItem item = (ColorItem)Items[index];
                _color = item.Color;
            }
            base.OnSelectedIndexChanged(e);
        }

        /// <summary>
        /// Draw a color entry.
        /// </summary>
        protected override void OnDrawItem(DrawItemEventArgs e)
        {
            int idx = e.Index;

            // Nothing selected?
            if (idx < 0)
                return;

            object obj = Items[idx];
            if (obj is ColorItem)
            {
                ColorItem item = (ColorItem)obj;

                // Is custom color?
                if (idx == 0)
                {
                    string name;
                    if (_color.IsEmpty)
                        name = "custom";
                    else
                        name = _crm.ToColorName(_color);

                    item = new ColorItem(_color, name);
                }

                XColor clr = item.Color;
                Graphics gfx = e.Graphics;
                Rectangle rect = e.Bounds;
                Brush textbrush = SystemBrushes.ControlText;
                if ((e.State & DrawItemState.Selected) == 0)
                {
                    gfx.FillRectangle(SystemBrushes.Window, rect);
                    textbrush = SystemBrushes.ControlText;
                }
                else
                {
                    gfx.FillRectangle(SystemBrushes.Highlight, rect);
                    textbrush = SystemBrushes.HighlightText;
                }

                // Draw color box
                if (!clr.IsEmpty)
                {
                    Rectangle box = new Rectangle(rect.X + 3, rect.Y + 1, rect.Height * 2, rect.Height - 3);
                    gfx.FillRectangle(new SolidBrush(clr.ToGdiColor()), box);
                    gfx.DrawRectangle(Pens.Black, box);
                }

                StringFormat format = new StringFormat(StringFormat.GenericDefault);
                format.Alignment = StringAlignment.Near;
                format.LineAlignment = StringAlignment.Center;
                rect.X += rect.Height * 2 + 3 + 3;
                gfx.DrawString(item.Name, Font, textbrush, rect, format);
            }
        }

        /// <summary>
        /// Represents a combo box item.
        /// </summary>
        struct ColorItem
        {
            public ColorItem(XColor color, string name)
            {
                Color = color;
                Name = name;
            }

            public override string ToString()
            {
                return Name;
            }

            public XColor Color;
            public string Name;
        }
    }
}
#endif
