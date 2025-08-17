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
            
    def visit_Str(self, node: ast.Str):
        """Visita strings literais (Python < 3.8)"""
        self._check_string_content(node.s, getattr(node, 'lineno', 0))
        self.generic_visit(node)
        
    def visit_Constant(self, node: ast.Constant):
        """Visita strings literais (Python > 3.8)"""
        if isinstance(node.value, str):
            self._check_string_content(node.s, getattr(node, 'lineno', 0))
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
    
    def _create_command_injection_finding(self, node: ast.Call, func_name: str, line_number: int) -> None:
        """Cria finding para command injection"""
    
    def _check_sql_injection(self, node: ast.Call, func_name: str, line_number: int) -> None:
        """Verifica SQL injection em queries"""
        
    def _check_hardcoded_secrets(self, node: ast.Assign) -> None:
        """Verifica hardcoded secrets em atribuições"""
        
    def _check_string_content(self, string_value: str, line_number: int) -> None:
        """Verifica conteúdo de strings por padrões suspeitos"""
        
    def _uses_tainted_data(self, node: ast.Call) -> bool:
        """Verifica se a chamada usa dados tainted (não confiáveis)"""