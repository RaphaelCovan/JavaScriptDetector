using Esprima;
using Esprima.Ast;
using System;
using System.Collections.Generic;

namespace JavaScriptDetector
{
    public class ASTVisitor
    {
        private List<(string Type, int Line, string jsCode, Risk Risk)> foundVulnerabilities;
        public List<(string Type, int Line, string jsCode, Risk Risk)> FoundVulnerabilities => foundVulnerabilities;

        private HashSet<string> sanitizationFunctions = new HashSet<string> { "sanitize", "escapeHTML", "sanitizeInput" };
        private HashSet<string> sanitizedVariables = new HashSet<string>();

        public ASTVisitor()
        {
            foundVulnerabilities = new List<(string Type, int Line, string jsCode, Risk Risk)>();
        }

        private void VisitAssignmentExpression(AssignmentExpression assignmentExpression)
        {
            if (assignmentExpression.Left is MemberExpression memberExpression)
            {
                if (memberExpression.Object is Identifier identifier && identifier.Name == "document")
                {
                    if (memberExpression.Property is Identifier property)
                    {
                        string propertyName = property.Name;
                        if (propertyName == "innerHTML" || propertyName == "outerHTML")
                        {
                            var lineNumber = memberExpression.Location.Start.Line;
                            if (!IsSanitized(assignmentExpression.Right))
                            {
                                foundVulnerabilities.Add(($"Direct {propertyName} Assignment", lineNumber, 
                                 assignmentExpression.ToString(), Risk.High));
                            }
                        }
                    }
                }
            }
        }

        private void VisitCallExpression(CallExpression callExpression)
        {
            if (callExpression.Callee is MemberExpression memberExpression)
            {
                // Verifica chamadas a innerHTML via getElementById
                if (memberExpression.Object is Identifier identifier && identifier.Name == "document" &&
                    memberExpression.Property is Identifier property && (property.Name == "getElementById" 
                    || property.Name == "write"))
                {
                    var lineNumber = callExpression.Location.Start.Line;
                    foundVulnerabilities.Add(("Potential XSS via " + property.Name, lineNumber, 
                        callExpression.ToString(), Risk.Medium));
                }
            }

            // Verifica se a chamada de função é uma função de sanitização
            if (callExpression.Callee is Identifier calleeIdentifier && 
                sanitizationFunctions.Contains(calleeIdentifier.Name))
            {
                foreach (var arg in callExpression.Arguments)
                {
                    if (arg is Identifier sanitizedVar)
                    {
                        sanitizedVariables.Add(sanitizedVar.Name);
                    }
                }
            }
        }

        private void VisitVariableDeclarator(VariableDeclarator variableDeclarator)
        {
            if (variableDeclarator.Init is CallExpression callExpression)
            {
                if (callExpression.Callee is Identifier identifier && sanitizationFunctions.Contains(identifier.Name))
                {
                    // Marcar a variável como sanitizada
                    sanitizedVariables.Add(variableDeclarator.Id.ToString());
                }
            }
        }

        private bool IsSanitized(Esprima.Ast.Expression expression)
        {
            if (expression is Identifier identifier)
            {
                return sanitizedVariables.Contains(identifier.Name);
            }
            return false;
        }

        public void Traverse(Node node)
        {
            Visit(node);
            foreach (var child in node.ChildNodes)
            {
                Traverse(child);
            }
        }

        public void Visit(Node node)
        {
            switch (node)
            {
                case AssignmentExpression assignmentExpression:
                    VisitAssignmentExpression(assignmentExpression);
                    break;
                case CallExpression callExpression:
                    VisitCallExpression(callExpression);
                    break;
                case VariableDeclarator variableDeclarator:
                    VisitVariableDeclarator(variableDeclarator);
                    break;
            }
        }
    }
}
