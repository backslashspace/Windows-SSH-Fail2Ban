using System.IO;
using System.Threading;

namespace F2B_SRV
{
    partial class Service
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.ServiceName = "F2B";
        }
    }
}
