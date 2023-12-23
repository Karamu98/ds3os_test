﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Loader.Forms
{
    public partial class CreateServerDialog : Form
    {
        private List<ServerConfig> ActiveServers;
        private Task CreateServerTask = null;
        private string MachinePublicIp = "";
        private MainForm ParentInstance;

        public CreateServerDialog(List<ServerConfig> InActiveServers, string InPublicIp, MainForm InParentInstance)
        {
            ActiveServers = InActiveServers;
            MachinePublicIp = InPublicIp;
            ParentInstance = InParentInstance;

            InitializeComponent();
        }

        private void OnSubmit(object sender, EventArgs e)
        {
            submitButton.Enabled = false;
            submitButton.Text = "Creating Server ...";

            usernameTextBox.Enabled = false;
            passwordTextBox.Enabled = false;

            ServerConfig ShardServer = null;

            foreach (ServerConfig Config in ActiveServers)
            {
                if (Config.AllowSharding && Config.WebAddress != "")
                {
                    ShardServer = Config;
                }
            }

            if (ShardServer == null)
            {
                MessageBox.Show("No servers are online that support sharding. Please try again later.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);

                DialogResult = DialogResult.Cancel;
                Close();
                return;
            }

            string Name = usernameTextBox.Text;
            string Password = passwordTextBox.Text;

            CreateServerTask = Task.Run(() =>
            {
                string Address = ShardServer.WebAddress;

                // Mainly used for debugging, not expected to be a standard path.
                if (Address.Contains("/" + MachinePublicIp + ":"))
                {
                    Address = Address.Replace("/" + MachinePublicIp + ":", "/127.0.0.1:");
                }

                WebUiApi.CreateServerResponse result = WebUiApi.CreateServer(Address, Name, Password);
                this.Invoke((MethodInvoker)delegate {
                    ProcessResult(result);
                });
            });
        }

        private void ProcessResult(WebUiApi.CreateServerResponse Result)
        {       
            CreateServerTask = null;
            DialogResult = DialogResult.OK;
            Visible = false;
            Close();
                 
            if (string.IsNullOrEmpty(Result.webUsername) ||
                string.IsNullOrEmpty(Result.webPassword) ||
                string.IsNullOrEmpty(Result.webUrl))
            {
                MessageBox.Show("Failed to create server, try again later.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                ParentInstance.Invoke((MethodInvoker)delegate {
                    ServerLoginDetailsDialog dialog = new ServerLoginDetailsDialog(Result.webUsername, Result.webPassword, Result.webUrl);
                    dialog.Owner = ParentInstance;
                    dialog.ShowDialog(ParentInstance);
                });
            }
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (CreateServerTask != null)
            {
                e.Cancel = true;
            }
        }
    }
}
