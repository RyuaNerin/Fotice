using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows.Forms;
using RyuaNerin;

namespace Fotice
{
    public partial class frmMain : Form
    {
        public frmMain()
        {
            InitializeComponent();

            var curVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;

            this.Text = string.Format("Fotice (rev. {0})", curVersion.Revision);
        }

        private async void frmMain_Load(object sender, EventArgs e)
        {
            var lastRelease = await Task.Factory.StartNew(() => LastestRelease.CheckNewVersion("RyuaNerin", "Fotice"));
            if (lastRelease != null)
            {
                MessageBox.Show(this, "새로운 버전이 있습니다!\n업데이트 해주세요.", this.Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                using (Process.Start(new ProcessStartInfo { UseShellExecute = true, FileName = lastRelease }))
                { }

                Application.Exit();
                return;
            }

            this.btnApply.Enabled = true;
            this.btnApply.Text = "적용";
        }

        private void btnApply_Click(object sender, EventArgs e)
        {
            try
            {
                if (Injector.Inject())
                {
                    MessageBox.Show(this, "적용 완료 :)", this.Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    Application.Exit();
                    return;
                }
            }
            catch
            { }

            MessageBox.Show(this, "적용 실패 :(", this.Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
