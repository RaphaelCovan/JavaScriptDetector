using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Jint;
using Esprima;
using Esprima.Ast;
using System.Text.RegularExpressions;
using LibGit2Sharp;

namespace JavaScriptDetector
{
    public partial class Form1 : Form
    {
        

        public Form1()
        {
            InitializeComponent();
            InitializeCustomComponents();
        }

        public Visitor Visitor
        {
            get => default;
            set
            {
            }
        }

        public ASTVisitor ASTVisitor
        {
            get => default;
            set
            {
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void InitializeCustomComponents()
        {
            
        }

        private void selectFolderButtonClick(object sender, EventArgs e)
        {
            using (var folderBrowserDialog = new FolderBrowserDialog())
            {
                if (folderBrowserDialog.ShowDialog() == DialogResult.OK)
                {
                    string selectedPath = folderBrowserDialog.SelectedPath;
                    analyseCodeInFolder(selectedPath);
                }
            }
        }

        private void analyzeFileButtonClick(object sender, EventArgs e)
        {
            using (var openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "JavaScript files (*.js)|*.js";
                openFileDialog.Title = "Select a JavaScript file";

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string filePath = openFileDialog.FileName;
                    analyzeSingleFile(filePath);
                }
            }
        }

        private void analyzeGithubRepoButtonClick(object sender, EventArgs e)
        {
            using (var inputDialog = new Form())
            {
                
                inputDialog.Size = new Size(500, 220);
                inputDialog.StartPosition = FormStartPosition.CenterParent; 

                var label = new Label()
                {
                    Left = 20,
                    Top = 20,
                    Text = "GitHub Repository URL:",
                    Font = new Font("Arial", 14F),
                    AutoSize = true
                };

                var textBox = new TextBox()
                {
                    Left = 20,
                    Top = 60,
                    Width = 440,
                    Font = new Font("Arial", 12F),
                    BorderStyle = BorderStyle.FixedSingle 
                };

                var confirmation = new Button()
                {
                    Text = "Analyse",
                    Left = textBox.Left + textBox.Width - 100,
                    Width = 100,
                    Height = 32,
                    Top = textBox.Top + textBox.Height + 20,
                    Font = new Font("Arial", 12F), 
                    BackColor = Color.LightGray,
                    FlatStyle = FlatStyle.Flat,
                    FlatAppearance = { BorderSize = 2, BorderColor = Color.Black }
                };

                confirmation.Click += (sender, e) => { inputDialog.DialogResult = DialogResult.OK; };
                inputDialog.Controls.Add(label);
                inputDialog.Controls.Add(textBox);
                inputDialog.Controls.Add(confirmation);

                inputDialog.AcceptButton = confirmation;

                if (inputDialog.ShowDialog() == DialogResult.OK)
                {
                    string repoUrl = textBox.Text;
                    AnalyzeGitHubRepository(repoUrl);
                }
            }
        }

        private void AnalyzeGitHubRepository(string repoUrl)
        {
            string tempPath = Path.Combine(Path.GetTempPath(), $"GitHubRepoAnalysis_{DateTime.Now.Ticks}");

            Directory.CreateDirectory(tempPath);

            try
            {
                
                Repository.Clone(repoUrl, tempPath);

                
                analyseCodeInFolder(tempPath);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"An error occurred while cloning the repository: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                
                CleanDirectory(tempPath);
            }
        }

        private void CleanDirectory(string directoryPath)
        {
            foreach (string subDirectory in Directory.GetDirectories(directoryPath))
            {
                CleanDirectory(subDirectory);
            }
            
        }

        private List<(string Type, int Line, string jsCode, Risk Risk)> analyseCode(string jsCode)
        {
            var cleanedCodeResult = cleanCode(jsCode);
            string cleanedCode = cleanedCodeResult.cleanedCode;
            var lineMapping = cleanedCodeResult.lineMapping;

            var visitor = new Visitor();
            visitor.FindTargetBlank(cleanedCode);
            visitor.FindUnprotectedCookies(cleanedCode);
            visitor.FindIframeWithoutSandbox(cleanedCode);
            visitor.FindHardcodedPasswords(cleanedCode);
            visitor.FindClientDomOpenRedirect(cleanedCode);
            visitor.FindJQueryDeprecatedSymbols(cleanedCode);
            visitor.FindLogForging(cleanedCode);
            visitor.FindHardcodedCryptographyKeys(cleanedCode);
            

            var vulnerabilities = visitor.GetVulnerabilities()
                .Select(v => (v.Type, lineMapping[v.Line - 1], v.jsCode, v.Risk))
                .ToList();

            var parser = new JavaScriptParser();
            try
            {
                var program = parser.ParseScript(jsCode);
                var astVisitor = new ASTVisitor();
                astVisitor.Traverse(program);
                vulnerabilities.AddRange(astVisitor.FoundVulnerabilities.Select(v =>
                {
                    int mappedLine = v.Line - 1;
                    if (mappedLine >= 0 && mappedLine < lineMapping.Count)
                    {
                        return (v.Type, lineMapping[mappedLine], v.jsCode, v.Risk);
                    }
                    else
                    {
                        return (v.Type, v.Line, v.jsCode, v.Risk); 
                    }
                }));

            }
            catch (Esprima.ParserException ex)
            {
                MessageBox.Show($"JavaScript parsing error: {ex.Message}", "Parsing Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            return vulnerabilities.OrderBy(v => v.Item2).ToList(); ;
        }

        private void analyseCodeInFolder(string folderPath)
        {
            var allFileVulnerabilities = new Dictionary<string, List<(string Type, int Line, string jsCode, Risk Risk)>>();

            var jsFiles = Directory.GetFiles(folderPath, "*.js", SearchOption.AllDirectories);

            foreach (var jsFile in jsFiles)
            {
                string jsCode = File.ReadAllText(jsFile);
                var vulnerabilities = analyseCode(jsCode);
                allFileVulnerabilities[jsFile] = vulnerabilities;

                
                foreach (var vulnerability in vulnerabilities)
                {
                    Console.WriteLine($"File: {jsFile}, Line: {vulnerability.Line}, Type: {vulnerability.Type}, Risk: {vulnerability.Risk}");
                }
            }

            
            saveReport(allFileVulnerabilities);
        }

        private void analyzeSingleFile(string filePath)
        {
            string jsCode = File.ReadAllText(filePath);
            var vulnerabilities = analyseCode(jsCode);

            var allFileVulnerabilities = new Dictionary<string, List<(string Type, int Line, string jsCode, Risk Risk)>>
            {
                { filePath, vulnerabilities }
            };

            saveReport(allFileVulnerabilities);
        }

        private void saveReport(Dictionary<string, List<(string Type, int Line, string jsCode, Risk Risk)>> allFileVulnerabilities)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog
            {
                Filter = "HTML files (*.html)|*.html",
                Title = "Save JavaScript Analysis Report"
            };

            if (saveFileDialog.ShowDialog() == DialogResult.OK && !string.IsNullOrWhiteSpace(saveFileDialog.FileName))
            {
                string htmlContent = createReport(allFileVulnerabilities);
                File.WriteAllText(saveFileDialog.FileName, htmlContent);
                MessageBox.Show("Analysis Report Created Successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        // Remove os comentários do código
        public static (string cleanedCode, List<int> lineMapping) cleanCode(string jsCode)
        {
            
            string singleLineCommentPattern = @"//.*?(?=\r?$)";
            string multiLineCommentPattern = @"/\*.*?\*/";

            var originalLines = jsCode.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None).ToList();
            var cleanedLines = new List<string>();
            var lineMapping = new List<int>();

            for (int i = 0; i < originalLines.Count; i++)
            {
                var line = originalLines[i];

                line = Regex.Replace(line, singleLineCommentPattern, string.Empty);

                line = Regex.Replace(line, multiLineCommentPattern, match =>
                {
                    int lineCount = match.Value.Count(c => c == '\n');
                    lineMapping.AddRange(Enumerable.Repeat(i + 1, lineCount));
                    return new string('\n', lineCount); 
                }, RegexOptions.Singleline);

                if (!string.IsNullOrWhiteSpace(line)) 
                {
                    cleanedLines.Add(line);
                    lineMapping.Add(i + 1);
                }
            }

            string cleanedCode = string.Join("\n", cleanedLines);
            return (cleanedCode, lineMapping);
        }


        private string createReport(Dictionary<string, List<(string Type, int Line, string jsCode, Risk Risk)>> allFileVulnerabilities)
        {
            var report = new StringBuilder();

            report.AppendFormat("<!DOCTYPE html>");
            report.AppendFormat("<html lang=\"en\">");
            report.AppendFormat("<head>");
            report.AppendFormat("    <meta charset=\"UTF-8\">");
            report.AppendFormat("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            report.AppendFormat("    <title>JavaScript Analysis Report</title>");
            report.AppendFormat("    <style>");
            report.AppendFormat("        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f7f7f7; }}");
            report.AppendFormat("        .report-box {{ background-color: #fff; border: 1px solid #ddd; padding: 20px; margin-bottom: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}");
            report.AppendFormat("        pre {{ white-space: pre-wrap; word-wrap: break-word; background-color: #eee; border: 1px solid #ddd; padding: 20px; }}");
            report.AppendFormat("        .highlight-line {{ background-color: #FBFBA2; }}"); 
            report.AppendFormat("        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}");
            report.AppendFormat("        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}");
            report.AppendFormat("        th {{ background-color: #1A2467; color: white; }}");
            report.AppendFormat("        tr:nth-child(even){{ background-color: #f2f2f2; }}");
            report.AppendFormat("        tr:hover {{ background-color: #ddd; }}");

            
            report.AppendFormat("        .high-risk {{ background-color: #FFCDD2; font-weight: bold; color: red; }}");
            report.AppendFormat("        .medium-risk {{ background-color: #FFE0B2; font-weight: bold; color: orange; }}");
            report.AppendFormat("        .low-risk {{ background-color: #FFF9C4; font-weight: bold; color: yellow; }}");

            report.AppendFormat("    </style>");
            report.AppendFormat("</head>");
            report.AppendFormat("<body>");
            report.AppendFormat("    <h1>JavaScript Analysis Report</h1>");

            foreach (var fileEntry in allFileVulnerabilities)
            {
                var filePath = fileEntry.Key;
                var vulnerabilities = fileEntry.Value;

                report.AppendFormat("    <div class=\"report-box\">");
                report.AppendFormat("        <h2>File: {0}</h2>", System.Security.SecurityElement.Escape(Path.GetFileName(filePath)));
                report.AppendFormat("        <h3>Code Content:</h3>");
                report.AppendFormat("        <pre>");

                
                var codeLines = File.ReadAllLines(filePath);
                var highlightedCode = new StringBuilder();
                for (int i = 0; i < codeLines.Length; i++)
                {
                    var lineNumber = i + 1;
                    var lineText = System.Security.SecurityElement.Escape(codeLines[i]);
                    
                    if (vulnerabilities.Any(v => v.Line == lineNumber))
                    {
                        highlightedCode.AppendFormat("<span class=\"highlight-line\">{0}</span>\n", lineText);
                    }
                    else
                    {
                        highlightedCode.AppendFormat("{0}\n", lineText);
                    }
                }
                report.Append(highlightedCode.ToString());

                report.AppendFormat("        </pre>");

                if (vulnerabilities.Any())
                {
                    report.AppendFormat("        <h3>Detected Vulnerabilities:</h3>");
                    report.AppendFormat("        <table>");
                    report.AppendFormat("            <tr><th>Type</th><th>Line</th><th>Code</th><th>Risk</th></tr>");
                    foreach (var vulnerability in vulnerabilities)
                    {
                        string riskClass = vulnerability.Risk switch
                        {
                            Risk.High => "high-risk",
                            Risk.Medium => "medium-risk",
                            Risk.Low => "low-risk",
                            _ => string.Empty
                        };

                        report.AppendFormat("            <tr><td>{0}</td><td>{1}</td><td>{2}</td><td class=\"{3}\">{4}</td></tr>",
                                            System.Security.SecurityElement.Escape(vulnerability.Type),
                                            vulnerability.Line,
                                            System.Security.SecurityElement.Escape(vulnerability.jsCode),
                                            riskClass,
                                            vulnerability.Risk);
                    }
                    report.AppendFormat("        </table>");
                }

                report.AppendFormat("    </div>");
            }

            report.AppendFormat("</body>");
            report.AppendFormat("</html>");

            return report.ToString();
        }
    }
}
