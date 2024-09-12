using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static ScintillaNET.Style;

namespace JavaScriptDetector
{
    public enum Risk
    {
        Low,
        Medium,
        High
    }

    public class Visitor
    {
        private List<(string Type, int Line, string jsCode, Risk Risk)> foundVulnerabilities;
        

        int vulnerabilities = 0;

        public Visitor()
        {
            foundVulnerabilities = new List<(string Type, int Line, string jsCode, Risk Risk)>();
        }


        public void FindTargetBlank(string jsCode)
        {
            
            var regexCreateElement = new Regex(@"var\s+(\w+)\s*=\s*document\.createElement\(['""]a['""]\);",
                RegexOptions.Singleline);

            var regexSetTargetBlank = new Regex(@"(\w+)\.setAttribute\(['""]target['""]\s*,\s*['""]_blank['""]\);",
                RegexOptions.Singleline);

            var regexDirectTargetBlank = new Regex(@"(\w+)\.target\s*=\s*['""]_blank['""];",
                RegexOptions.Singleline);

            var regexSetRel = new Regex(@"(\w+)\.setAttribute\(['""]rel['""]\s*,\s*['""]noopener noreferrer['""]\);",
                RegexOptions.Singleline);

            var regexDirectSetRel = new Regex(@"(\w+)\.rel\s*=\s*['""]noopener noreferrer['""];",
                RegexOptions.Singleline);

            var matchesCreateElement = regexCreateElement.Matches(jsCode);

            foreach (Match createElementMatch in matchesCreateElement)
            {
                var variableName = createElementMatch.Groups[1].Value;
                var afterCreateElementText = jsCode.Substring(createElementMatch.Index +
                    createElementMatch.Length);

                var targetBlankMatch = regexSetTargetBlank.Match(afterCreateElementText);

                if (!targetBlankMatch.Success)
                {
                    targetBlankMatch = regexDirectTargetBlank.Match(afterCreateElementText);
                }

                if (targetBlankMatch.Success && targetBlankMatch.Groups[1].Value == variableName)
                {
                    var relMatch = regexSetRel.Match(afterCreateElementText, targetBlankMatch.Index +
                        targetBlankMatch.Length);

                    if (!relMatch.Success)
                    {
                        relMatch = regexDirectSetRel.Match(afterCreateElementText, targetBlankMatch.Index +
                            targetBlankMatch.Length);
                    }

                    if (!(relMatch.Success && relMatch.Groups[1].Value == variableName))
                    {
                        int lineNumber = 1 + Regex.Matches(jsCode.Substring(0,
                            createElementMatch.Index), @"\n").Count;
                        foundVulnerabilities.Add(("Unsafe Use of Target Blank", lineNumber,
                            createElementMatch.Value, Risk.High));
                        vulnerabilities++;
                    }
                }
            }
        }




        public void FindIframeWithoutSandbox(string jsCode)
        {
            var lines = jsCode.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            var iframeCreationRegex = new Regex(@"var (\w+) = document\.createElement\(['""]iframe['""]\)", RegexOptions.IgnoreCase);
            var iframeSandboxRegex = new Regex(@"(\w+)\.setAttribute\(['""]sandbox['""], ['""](.+?)['""]\)", RegexOptions.IgnoreCase);
            var iframeAppendRegex = new Regex(@"document\.body\.appendChild\((\w+)\)", RegexOptions.IgnoreCase);

            Dictionary<string, (int LineNumber, bool HasSandbox)> iframeTracker = new Dictionary<string, (int LineNumber, bool HasSandbox)>();

            for (int i = 0; i < lines.Length; i++)
            {
                var creationMatch = iframeCreationRegex.Match(lines[i]);
                if (creationMatch.Success)
                {
                    var iframeVar = creationMatch.Groups[1].Value;
                    iframeTracker[iframeVar] = (i + 1, false);
                }

                var sandboxMatch = iframeSandboxRegex.Match(lines[i]);
                if (sandboxMatch.Success)
                {
                    var iframeVar = sandboxMatch.Groups[1].Value;
                    if (iframeTracker.ContainsKey(iframeVar))
                    {
                        iframeTracker[iframeVar] = (iframeTracker[iframeVar].LineNumber, true);
                    }
                }
            }

            foreach (var appendMatch in lines.Select((value, index) => new { value, index }))
            {
                var match = iframeAppendRegex.Match(appendMatch.value);
                if (match.Success)
                {
                    var iframeVar = match.Groups[1].Value;
                    if (iframeTracker.ContainsKey(iframeVar) && !iframeTracker[iframeVar].HasSandbox)
                    {
                        foundVulnerabilities.Add(("Client Use of Iframe Without Sandbox", appendMatch.index + 1, appendMatch.value, Risk.High));
                        vulnerabilities++;
                    }
                }
            }
        }

        public void FindUnprotectedCookies(string jsCode)
        {
            var lines = jsCode.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            var cookieRegex = new Regex(@"document\.cookie\s*=\s*['""][^'""]*['""]", RegexOptions.IgnoreCase);

            for (int i = 0; i < lines.Length; i++)
            {
                var match = cookieRegex.Match(lines[i]);
                if (match.Success)
                {
                    bool isSecure = Regex.IsMatch(match.Value, "secure", RegexOptions.IgnoreCase);
                    bool isHttpOnly = Regex.IsMatch(match.Value, "httponly", RegexOptions.IgnoreCase);

                    if (!isSecure && !isHttpOnly)
                    {
                        foundVulnerabilities.Add(("Unprotected Cookie", i + 1, lines[i], Risk.High));
                        vulnerabilities++;
                    }
                    else if (!isSecure || !isHttpOnly)
                    {
                        foundVulnerabilities.Add(("Unprotected Cookie", i + 1, lines[i], Risk.Medium));
                        vulnerabilities++;
                    }
                }
            }
        }

        public void FindHardcodedPasswords(string jsCode)
        {
            var lines = jsCode.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

            var passwordRegex = new Regex(@"\b\w*password\w*\b\s*[:=]\s*[^;]+", 
                RegexOptions.IgnoreCase);

            for (int i = 0; i < lines.Length; i++)
            {
                var match = passwordRegex.Match(lines[i]);
                if (match.Success)
                {
                    string matchedLine = match.Value;
                    foundVulnerabilities.Add(("Use of Potential Hardcoded Password", i + 1, 
                        lines[i], Risk.Medium));
                    vulnerabilities++;
                }
            }
        }

        public void FindClientDomOpenRedirect(string jsCode)
        {
            var lines = jsCode.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

            var redirectRegexHref = new Regex(@"window\.location\.href\s*=\s*(.*);", RegexOptions.IgnoreCase);

            var redirectRegexReplace = new Regex(@"window\.location\.replace\s*\(\s*(.*)\s*\);", RegexOptions.IgnoreCase);

            var redirectRegexHash = new Regex(@"window\.location\.hash\s*=\s*(.*);", RegexOptions.IgnoreCase);

            var redirectRegexFormAction = new Regex(@"<form[^>]*\saction\s*=\s*['""](.*)['""]", RegexOptions.IgnoreCase);

            for (int i = 0; i < lines.Length; i++)
            {
                var matchHref = redirectRegexHref.Match(lines[i]);
                if (matchHref.Success)
                {
                    string potentialRedirectUrl = matchHref.Groups[1].Value;
                    if (!IsWhitelisted(potentialRedirectUrl) && !IsSanitized(potentialRedirectUrl, jsCode))
                    {
                        foundVulnerabilities.Add(("Client DOM Open Redirect", i + 1, lines[i], Risk.High));
                        vulnerabilities++;
                    }
                }

                var matchReplace = redirectRegexReplace.Match(lines[i]);
                if (matchReplace.Success)
                {
                    string potentialRedirectUrl = matchReplace.Groups[1].Value;
                    if (!IsWhitelisted(potentialRedirectUrl) && !IsSanitized(potentialRedirectUrl, jsCode))
                    {
                        foundVulnerabilities.Add(("Client DOM Open Redirect", i + 1, lines[i], Risk.High));
                        vulnerabilities++;
                    }
                }

                var matchHash = redirectRegexHash.Match(lines[i]);
                if (matchHash.Success)
                {
                    string potentialRedirectUrl = matchHash.Groups[1].Value;
                    if (!IsWhitelisted(potentialRedirectUrl) && !IsSanitized(potentialRedirectUrl, jsCode))
                    {
                        foundVulnerabilities.Add(("Client DOM Open Redirect", i + 1, lines[i], Risk.High));
                        vulnerabilities++;
                    }
                }

                var matchFormAction = redirectRegexFormAction.Match(lines[i]);
                if (matchFormAction.Success)
                {
                    string potentialRedirectUrl = matchFormAction.Groups[1].Value;
                    if (!IsWhitelisted(potentialRedirectUrl) && !IsSanitized(potentialRedirectUrl, jsCode))
                    {
                        foundVulnerabilities.Add(("Client DOM Open Redirect", i + 1, lines[i], Risk.High));
                        vulnerabilities++;
                    }
                }
            }
        }

        public void FindJQueryDeprecatedSymbols(string jsCode)
        {
            var lines = jsCode.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

            
            var deprecatedMethods = new Regex(@"\$\(\s*['""][^'""]+['""]\s*\)\.(bind|live|delegate|size|toggle|andSelf)\s*\(",
                RegexOptions.IgnoreCase);

            for (int i = 0; i < lines.Length; i++)
            {
                var match = deprecatedMethods.Match(lines[i]);
                if (match.Success)
                {
                    string methodName = match.Groups[1].Value;
                    foundVulnerabilities.Add(("Client JQuery Deprecated Symbols - " + methodName,
                    i + 1, lines[i], Risk.Medium));
                    vulnerabilities++;
                }
            }
        }

        public void FindLogForging(string jsCode)
        {
            var lines = jsCode.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            var logRegex = new Regex(@"console\.(log|error)\((.+)\)", RegexOptions.IgnoreCase);

            for (int i = 0; i < lines.Length; i++)
            {
                var match = logRegex.Match(lines[i]);
                if (match.Success)
                {
                    var loggedExpression = match.Groups[2].Value.Trim();

                    var variableValue = IsVariable(loggedExpression) ? 
                        TraceVariable(loggedExpression, lines, i) : loggedExpression;

                    if (IsPotentiallyVulnerableInput(variableValue, jsCode) && 
                        !IsSanitized(variableValue, jsCode))
                    {
                        foundVulnerabilities.Add(("Log Forging", i + 1, lines[i], Risk.High));
                        vulnerabilities++;
                    }
                }
            }
        }

        public void FindHardcodedCryptographyKeys(string jsCode)
        {
            var lines = jsCode.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

            var cryptoKeyRegex = new Regex(@"\b\w*(key|secret|token|password|passphrase|salt)\w*\b\s*[:=]\s*['""][^'""]+['""]",
                RegexOptions.IgnoreCase);

            for (int i = 0; i < lines.Length; i++)
            {
                var match = cryptoKeyRegex.Match(lines[i]);
                if (match.Success)
                {
                    string matchedLine = match.Value;
                    foundVulnerabilities.Add(("Use of Hardcoded Cryptographic Key", i + 1, lines[i], Risk.High));
                    vulnerabilities++;
                }
            }
        }

        private bool IsWhitelisted(string url)
        {
            
            var whitelistPatterns = new List<string>
            {
                @"^https:\/\/example\.com\/.*", 
                @"^http:\/\/localhost",         
                
            };

            foreach (var pattern in whitelistPatterns)
            {
                if (Regex.IsMatch(url.Trim('"'), pattern))
                {
                    return true;
                }
            }
            return false;
        }

        private bool IsSanitized(string variableName, string jsCode)
        {
            var sanitizationRegex = new Regex(@$"{variableName}\s*=\s*(sanitize\(|escapeHTML\(|sanitizeInput\(|sanitizeUrl\().*;", RegexOptions.IgnoreCase);

            return sanitizationRegex.IsMatch(jsCode);
        }

        private bool IsPotentiallyVulnerableInput(string value, string jsCode)
        {
            var userInputs = new[] { "userInput", "formInput", "user", "data", "input" };
            return userInputs.Any(input => value.Contains(input)) || value.Contains("+");
        }


        private bool IsVariable(string expression)
        {
            return !expression.StartsWith("\"") && !expression.StartsWith("'") &&
                !expression.StartsWith("{") && !expression.StartsWith("[");
        }

        private string TraceVariable(string variableName, string[] lines, int currentLineIndex)
        {
            for (int i = currentLineIndex - 1; i >= 0; i--)
            {
                var line = lines[i];
                var assignmentRegex = new Regex($@"\b{variableName}\s*=\s*(.+);", RegexOptions.IgnoreCase);
                var match = assignmentRegex.Match(line);
                if (match.Success)
                {
                    return match.Groups[1].Value.Trim();
                }
            }
            return variableName; 
        }

        public List<(string Type, int Line, string jsCode, Risk Risk)> GetVulnerabilities()
        {
            return foundVulnerabilities;
        }
    }
}