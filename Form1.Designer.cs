namespace JavaScriptDetector
{
    partial class Form1
    {
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
        private System.Windows.Forms.Button selectFolderButton;
        private System.Windows.Forms.Button analyzeFileButton;
        private System.Windows.Forms.Button analyzeGithubRepoButton;

        private void InitializeComponent()
        {
            this.tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            this.selectFolderButton = new System.Windows.Forms.Button();
            this.analyzeFileButton = new System.Windows.Forms.Button();
            this.analyzeGithubRepoButton = new System.Windows.Forms.Button();

            this.SuspendLayout();

            this.tableLayoutPanel1.ColumnCount = 1;
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel1.RowCount = 3;
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 33.33F));
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 33.33F));
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 33.33F));
            this.tableLayoutPanel1.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel1.Controls.Add(this.analyzeGithubRepoButton, 0, 0);
            this.tableLayoutPanel1.Controls.Add(this.analyzeFileButton, 0, 1);
            this.tableLayoutPanel1.Controls.Add(this.selectFolderButton, 0, 2);
            this.tableLayoutPanel1.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel1.Name = "tableLayoutPanel1";
            this.tableLayoutPanel1.Size = new System.Drawing.Size(400, 400);
            this.tableLayoutPanel1.TabIndex = 0;

            this.selectFolderButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.selectFolderButton.Font = new System.Drawing.Font("Arial", 12F);
            this.selectFolderButton.Location = new System.Drawing.Point(75, 250);
            this.selectFolderButton.Name = "selectFolderButton";
            this.selectFolderButton.Size = new System.Drawing.Size(250, 60);
            this.selectFolderButton.TabIndex = 2;
            this.selectFolderButton.Text = "Analyse Folder";
            this.selectFolderButton.UseVisualStyleBackColor = false;
            this.selectFolderButton.FlatStyle = FlatStyle.Flat; 
            this.selectFolderButton.FlatAppearance.BorderSize = 2;
            this.selectFolderButton.FlatAppearance.BorderColor = Color.Black; 
            this.selectFolderButton.BackColor = Color.LightGray; 
            this.selectFolderButton.ForeColor = Color.Black; 
            this.selectFolderButton.Click += new System.EventHandler(this.selectFolderButtonClick);

            this.analyzeFileButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.analyzeFileButton.Font = new System.Drawing.Font("Arial", 12F); 
            this.analyzeFileButton.Location = new System.Drawing.Point(75, 160);
            this.analyzeFileButton.Name = "analyzeFileButton";
            this.analyzeFileButton.Size = new System.Drawing.Size(250, 60);
            this.analyzeFileButton.TabIndex = 1;
            this.analyzeFileButton.Text = "Analyse File";
            this.analyzeFileButton.UseVisualStyleBackColor = false;
            this.analyzeFileButton.FlatStyle = FlatStyle.Flat; 
            this.analyzeFileButton.FlatAppearance.BorderSize = 2; 
            this.analyzeFileButton.FlatAppearance.BorderColor = Color.Black; 
            this.analyzeFileButton.BackColor = Color.LightGray; 
            this.analyzeFileButton.ForeColor = Color.Black; 
            this.analyzeFileButton.Click += new System.EventHandler(this.analyzeFileButtonClick);

            this.analyzeGithubRepoButton.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.analyzeGithubRepoButton.Font = new System.Drawing.Font("Arial", 12F); 
            this.analyzeGithubRepoButton.Location = new System.Drawing.Point(75, 70);
            this.analyzeGithubRepoButton.Name = "analyzeGithubRepoButton";
            this.analyzeGithubRepoButton.Size = new System.Drawing.Size(250, 60);
            this.analyzeGithubRepoButton.TabIndex = 0;
            this.analyzeGithubRepoButton.Text = "Analyse GitHub Repo";
            this.analyzeGithubRepoButton.UseVisualStyleBackColor = false;
            this.analyzeGithubRepoButton.FlatStyle = FlatStyle.Flat; 
            this.analyzeGithubRepoButton.FlatAppearance.BorderSize = 2; 
            this.analyzeGithubRepoButton.FlatAppearance.BorderColor = Color.Black; 
            this.analyzeGithubRepoButton.BackColor = Color.LightGray; 
            this.analyzeGithubRepoButton.ForeColor = Color.Black; 
            this.analyzeGithubRepoButton.Click += new System.EventHandler(this.analyzeGithubRepoButtonClick);

            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(400, 400);
            this.Controls.Add(this.tableLayoutPanel1);
            this.Name = "Form1";
            this.Text = "JavaScript Detector";
            this.ResumeLayout(false);
        }

    }
}
