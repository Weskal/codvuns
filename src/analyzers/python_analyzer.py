import ast
import re
from typing import List, Dict, Any, Optional, Set, Union
from pathlib import Path
import logging

from .base_analyzer import BaseAnalyzer
from ..models.finding import Finding, Severity

class PythonASTVisitor(ast.NodeVisitor):
    """
    Visitor ou padrão personalizado para analisar/percorrer árvore AST Python.
    
    Percorre todos os nós da AST procurando por padrões perigosos e 
    vulnerabilidades de segurança específicas para Python.
    """
    
    def __init__(self, file_path: str, content: str):
        self.file_path = file_path
        self.content = content
        self.findings: List[Finding] = []
        self.lines = content.splitlines()
        
        # Conjuntos de funções/módulos considerados perigosos (add mais depois)
        self.dangerous_functions = {
            'eval','exec','compile','__import__'
        }
        
        self.dangerous_modules = {
            'os.system', 'subprocess.call', 'subprocess.run', 
            'subprocess.Popen', 'commands.getoutput'
        }
        
        self.sql_functions = {
            'execute', 'executemany', 'query'
        }
        
        # Tracking de variáveis tainted (dados não confiáveis)
        self.tainted_vars: Set[str] = set()
        self.user_input_functions = {
            'input', 'raw_input', 'request.form', 'request.args',
            'request.json', 'request.data'
        }
        
    def visit_Call(self, node: ast.Call) -> None:
        """Visita chamadas de função como exec, eval..."""
        
        try:
            func_name = self._get_function_name(node.func)
            line_number = getattr(node, 'lineno', 0)
            
            # Detecta funções perigosas
            if func_name in self.dangerous_functions:
                self._create_dangerous_function_finding(node, func_name, line_number)
                
            # Detecta chamadas de sistema perigosas
            elif func_name in self.dangerous_modules:
                self._create_command_injection_finding(node, func_name, line_number)
            
            # Detecta potencial SQL injection
            elif any(sql_func in func_name for sql_func in self.sql_functions):
                self._check_sql_injection(node, func_name, line_number)
            
            # Detecta input do usuário (tainted tracking)
            
            elif func_name in self.user_input_functions:
                self._mark_user_input(node, line_number)
                
        except Exception as e:
            logging.warning(f"Erro ao analisar chamada de sistema em {self.file_path}:{line_number}: {e}")
            
        self.generic_visit(node)
        
    def visit_Assign(self, node: ast.Assign) -> None:
        """Visita atribuições de variáveis ex: x = eval(user_input)"""
        
        try:
            if isinstance(node.value, ast.Call):
                func_name = self._get_function_name(node.value.func)
                if func_name in self.user_input_functions:
                    # Marca variáveis que recebem input do usuário
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_vars.add(target.id)
            # Verifica se existe hardcoded secrets nas atribuições de variáveis
            self._check_hardcoded_secrets(node)
        except Exception as e:
            line_number = getattr(node, 'lineno', 0)
            logging.warning(f"Erro ao analisar assign em {self.file_path}:{line_number}: {e}")
            
    def visit_Str(self, node: ast.Str) -> None:
        """Visita strings literais (Python < 3.8)"""
        self._check_string_content(node.s, getattr(node, 'lineno', 0))
        self.generic_visit(node)
        
    def visit_Constant(self, node: ast.Constant) -> None:
        """Visita strings literais (Python > 3.8)"""
        if isinstance(node.value, str):
            self._check_string_content(node.value, getattr(node, 'lineno', 0))
        self.generic_visit(node)
        
    def _get_function_name(self, func_node: ast.AST) -> str:
        """Extrai nome da função"""
        
        try:
            if isinstance(func_node, ast.Name):
                return func_node.id
            elif isinstance(func_node, ast.Attribute):
                # Para chamadas como os.system, request.form...
                value_name = self._get_function_name(func_node.value) if hasattr(func_node.value, 'id') else 'unknown'
                return f"{value_name}.{func_node.attr}"
            elif isinstance(func_node, ast.Call):
                return self._get_function_name(func_node.func)
            else: 
                return 'unknown'
        except :
            return 'unknown'
            
    def _create_dangerous_function_finding(self, node: ast.Call, func_name: str, line_number: int) -> None:
        """Cria finding para funções perigosas"""

        line_content = self._get_line_content(line_number)
        
        # Verifica se usa dados contaminados/tainted
        
        severity = Severity.HIGH
        if self._uses_tainted_data(node):
            severity = Severity.CRITICAL
            
        finding = Finding(
            file_path=self.file_path,
            line_number=line_number,
            rule_id=f"DANGEROUS_FUNCTION_{func_name.upper()}",
            severity=severity,
            message=f"Uso de função perigosa '{func_name}()' detectado",
            code_snippet=line_content,
            category="dangerous_functions"
        )
        self.findings.append(finding)
        
    def _create_command_injection_finding(self, node: ast.Call, func_name: str, line_number: int) -> None:
        """Cria finding para command injection"""
        
        line_content = self._get_line_content(line_number)
        
        # Verifica se concatena strings ou usa dados contaminados
        
        severity = Severity.MEDIUM
        if self._has_string_concatenation(node) or self._uses_tainted_data(node):
            severity = Severity.CRITICAL
            
        finding = Finding(
            file_path=self.file_path,
            line_number=line_number,
            rule_id=f"COMMAND_INJECTION_001",
            severity=severity,
            message=f"Potencial command injection em '{func_name}()'",
            code_snippet=line_content,
            category="injection"
        )
        
        self.findings.append(finding)
    
    def _check_sql_injection(self, node: ast.Call, func_name: str, line_number: int) -> None:
        """Verifica SQL injection em queries"""
        
        line_content = self._get_line_content(line_number)
        
        # Verifica se há concatenação de strings na query
        
        if self._has_string_concatenation(node) or self._uses_tainted_data(node):
            finding = Finding(
            file_path=self.file_path,
            line_number=line_number,
            rule_id=f"COMMAND_INJECTION_001",
            severity=Severity.HIGH,
            message=f"Potencial SQL injection em '{func_name}()'",
            code_snippet=line_content,
            category="injection"
        )
        
    def _check_hardcoded_secrets(self, node: ast.Assign) -> None:
        """Verifica hardcoded secrets em atribuições"""
        
        try:
            line_number = getattr(node, 'lineno', 0)
            line_content = self._get_line_content(line_number)
            
            # Padrões de variáveis suspeitas
            secret_patterns = [
                r'(?i)(password|pwd|passwd|secret|key|token|api_key)',
                r'(?i)(auth|credential|login)'
            ]
            
            # Verifica os nomes das variáveis
            
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    for pattern in secret_patterns:
                        if re.search(pattern, var_name):
                            if isinstance(node.value, (ast.Str, ast.Constant)):
                                value = node.value.s if isinstance(node.value, ast.Str) else node.value.value
                                if isinstance(value, str) and len(value) > 3:
                                    finding = Finding(
                                    file_path=self.file_path,
                                    line_number=line_number,
                                    rule_id=f"HARDCODED_SECRET_001",
                                    severity=Severity.HIGH,
                                    message=f"Potencial hardcoded secret na variável '{var_name}()'",
                                    code_snippet=line_content,
                                    category="hardcoded_secrets"
                                )
                                    
                                self.findings.append(finding)
                                break
        except Exception as e:
            logging.warning(f"Erro ao verificar hardcoded secrets {e}")
            
    def _check_string_content(self, string_value: str, line_number: int) -> None:
        """Verifica conteúdo de strings por padrões suspeitos"""
        
        try:
            # Padrões para diferentes tipos de secrets
            patterns = {
                "API_KEY": r'(?i)api[_-]?key[_-]?[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                "PASSWORD": r'(?i)password[_-]?[:=]\s*["\']([^"\']{6,})["\']',
                "SECRET": r'(?i)secret[_-]?[:=]\s*["\']([a-zA-Z0-9]{16,})["\']',
                "TOKEN": r'(?i)token[_-]?[:=]\s*["\']([a-zA-Z0-9]{20,})["\']'
            }
            
            for secret_type, pattern in patterns.items():
                if re.search(pattern, string_value):
                    line_content = self._get_line_content(line_number)
                    finding = Finding(
                    file_path=self.file_path,
                    line_number=line_number,
                    rule_id=f"HARDCODED_{secret_type}_001",
                    severity=Severity.MEDIUM,
                    message=f"Potencial {secret_type.lower()} hardcoded detectado",
                    code_snippet=line_content,
                    category="hardcoded_secrets"
                )
                self.findings.append(finding)
                break
        except Exception as e:
            logging.warning(f"Erro ao verificar string content: {e}")
        
    def _uses_tainted_data(self, node: ast.Call) -> bool:
        """Verifica se a chamada usa dados tainted (não confiáveis)"""
        
        try:
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    return True
                elif isinstance(arg, ast.BinOp): # Concatenação
                    return self._binop_uses_tainted(arg)
            return False
        except:
            return False
        
    def _has_string_concatenation(self, node: ast.Call) -> bool:
        """"Verifica se há concatenação de strings nos argumentos"""
        
        try:
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    return True
            return False
        except:
            return False
    
    def _binop_uses_tainted(self, node: ast.BinOp) -> bool:
        """Verifica se operação binária usa dados tainted"""
        try:
            if isinstance(node.left, ast.Name) and node.left.id in self.tainted_vars:
                return True
            if isinstance(node.right, ast.Name) and node.right.id in self.tainted_vars:
                return True
            return False
        
        except:
            return False
        
    def _mark_user_input(self, node: ast.Call, line_number:int) -> None:
        """Marca que foi detectado input do usuário"""
        # apenas um tracking de input
        
    def _get_line_content(self, line_number: int) -> str:
        """Obtém conteúdo de uma linha específica"""
        try:
            if 1 <= line_number <= len(self.lines):
                return self.lines[line_number - 1].strip()
            return ""
        except:
            return ""

