import pytest
import unittest
from unittest.mock import Mock, patch, mock_open, MagicMock
import tempfile
import os
import ast
from pathlib import Path
from typing import List, Dict, Any

# Imports que seriam do projeto real
from src.analyzers.python_analyzer import PythonAnalyzer, PythonASTVisitor
from src.models.finding import Finding, Severity
from src.models.rule import Rule, RuleType, VulnerabilityCategory, RuleMetadata


class TestPythonASTVisitor(unittest.TestCase):
    """Testes para a classe PythonASTVisitor"""
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        self.file_path = "test_file.py"
        self.sample_content = """
import os
password = "hardcoded123"
user_input = input("Enter data: ")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
eval(user_input)
os.system("rm -rf " + file_path)
"""
        self.visitor = PythonASTVisitor(self.file_path, self.sample_content)
    
    def test_visitor_initialization(self):
        """Testa inicialização do visitor"""
        self.assertEqual(self.visitor.file_path, self.file_path)
        self.assertEqual(self.visitor.content, self.sample_content)
        self.assertIsInstance(self.visitor.findings, list)
        self.assertEqual(len(self.visitor.findings), 0)
        
        # Verifica se conjuntos perigosos foram inicializados
        self.assertIn('eval', self.visitor.dangerous_functions)
        self.assertIn('os.system', self.visitor.dangerous_modules)
        self.assertIn('execute', self.visitor.sql_functions)
    
    def test_get_function_name_simple(self):
        """Testa extração de nome de função simples"""
        # Testa ast.Name
        node = ast.Name(id='eval', ctx=ast.Load())
        result = self.visitor._get_function_name(node)
        self.assertEqual(result, 'eval')
        
        # Testa função desconhecida
        unknown_node = ast.Constant(value=42)
        result = self.visitor._get_function_name(unknown_node)
        self.assertEqual(result, 'unknown')
    
    def test_get_function_name_attribute(self):
        """Testa extração de nome com atributos (os.system)"""
        # Simula os.system
        node = ast.Attribute(
            value=ast.Name(id='os', ctx=ast.Load()),
            attr='system',
            ctx=ast.Load()
        )
        result = self.visitor._get_function_name(node)
        self.assertEqual(result, 'os.system')
    
    def test_dangerous_function_detection(self):
        """Testa detecção de funções perigosas"""
        code = "eval(user_input)"
        tree = ast.parse(code)
        
        visitor = PythonASTVisitor("test.py", code)
        visitor.visit(tree)
        
        # Deve encontrar pelo menos um finding
        self.assertGreater(len(visitor.findings), 0)
        
        # Verifica se encontrou eval
        eval_findings = [f for f in visitor.findings if 'EVAL' in f.rule_id]
        self.assertGreater(len(eval_findings), 0)
        
        finding = eval_findings[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn('eval', finding.message.lower())
    
    def test_sql_injection_detection(self):
        """Testa detecção de SQL injection"""
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        tree = ast.parse(code)
        
        visitor = PythonASTVisitor("test.py", code)
        visitor.visit(tree)
        
        sql_findings = [f for f in visitor.findings if 'SQL_INJECTION' in f.rule_id]
        self.assertGreater(len(sql_findings), 0)
        
        finding = sql_findings[0]
        self.assertEqual(finding.severity, Severity.HIGH)
    
    def test_command_injection_detection(self):
        """Testa detecção de command injection"""
        code = 'os.system("rm -rf " + file_path)'
        tree = ast.parse(code)
        
        visitor = PythonASTVisitor("test.py", code)
        visitor.visit(tree)
        
        cmd_findings = [f for f in visitor.findings if 'COMMAND_INJECTION' in f.rule_id]
        self.assertGreater(len(cmd_findings), 0)
        
        finding = cmd_findings[0]
        self.assertEqual(finding.severity, Severity.MEDIUM)
    
    def test_hardcoded_secrets_detection(self):
        """Testa detecção de hardcoded secrets"""
        code = 'password = "secret123"\napi_key = "abc123def456"'
        tree = ast.parse(code)
        
        visitor = PythonASTVisitor("test.py", code)
        visitor.visit(tree)
        
        secret_findings = [f for f in visitor.findings if 'SECRET' in f.rule_id]
        self.assertGreater(len(secret_findings), 0)
    
    def test_tainted_data_tracking(self):
        """Testa rastreamento de dados tainted"""
        code = '''
user_input = input("Enter: ")
eval(user_input)
'''
        tree = ast.parse(code)
        
        visitor = PythonASTVisitor("test.py", code)
        visitor.visit(tree)
        
        # Deve marcar user_input como tainted
        self.assertIn('user_input', visitor.tainted_vars)
        
        # eval com dados tainted deve ser CRITICAL
        eval_findings = [f for f in visitor.findings if 'EVAL' in f.rule_id]
        if eval_findings:
            self.assertEqual(eval_findings[0].severity, Severity.CRITICAL)
    
    def test_string_concatenation_detection(self):
        """Testa detecção de concatenação de strings"""
        # Simula um nó de concatenação
        concat_node = ast.BinOp(
            left=ast.Str(s="SELECT * FROM users WHERE id = "), # type: ignore
            op=ast.Add(),
            right=ast.Name(id='user_id', ctx=ast.Load())
        )
        
        call_node = ast.Call(
            func=ast.Attribute(
                value=ast.Name(id='cursor', ctx=ast.Load()),
                attr='execute',
                ctx=ast.Load()
            ),
            args=[concat_node],
            keywords=[]
        )
        
        result = self.visitor._has_string_concatenation(call_node)
        self.assertTrue(result)
    
    def test_line_content_retrieval(self):
        """Testa obtenção de conteúdo da linha"""
        content = "line1\nline2\nline3"
        visitor = PythonASTVisitor("test.py", content)
        
        self.assertEqual(visitor._get_line_content(1), "line1")
        self.assertEqual(visitor._get_line_content(2), "line2")
        self.assertEqual(visitor._get_line_content(3), "line3")
        self.assertEqual(visitor._get_line_content(10), "")  # Linha inexistente
    
    def test_syntax_error_handling(self):
        """Testa tratamento de erros de sintaxe"""
        invalid_code = "def invalid_syntax("  # Sintaxe inválida
        
        with patch('logging.warning') as mock_warning:
            visitor = PythonASTVisitor("test.py", invalid_code)
            # Não deve gerar exceção
            self.assertIsInstance(visitor, PythonASTVisitor)


class TestPythonAnalyzer(unittest.TestCase):
    """Testes para a classe PythonAnalyzer"""
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        self.analyzer = PythonAnalyzer()
        self.sample_python_code = '''
import os
import subprocess

password = "hardcoded123"
api_key = "abc123def456ghi789"

def vulnerable_function():
    user_input = input("Enter command: ")
    os.system("echo " + user_input)
    
    sql_query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(sql_query)
    
    eval(user_input)
    exec(malicious_code)

def safe_function():
    print("This is safe")
'''
        
        # Mock rules
        self.mock_rules = [
            Mock(
                id="TEST_RULE_1",
                rule_type=Mock(value='regex'),
                patterns=["password\\s*=\\s*[\"'][^\"']+[\"']"],
                case_sensitive=True,
                multiline=False,
                severity=Severity.MEDIUM,
                description="Test rule",
                category=Mock(value='hardcoded_secrets'),
                confidence_threshold=0.8,
                target_languages=["python"]
            )
        ]
    
    def test_analyzer_initialization(self):
        """Testa inicialização do analyzer"""
        self.assertIsInstance(self.analyzer, PythonAnalyzer)
        self.assertIsInstance(self.analyzer.regex_patterns, dict)
        
        # Verifica se padrões regex foram definidos
        self.assertIn("SQL_INJECTION_REGEX", self.analyzer.regex_patterns)
        self.assertIn("COMMAND_INJECTION_REGEX", self.analyzer.regex_patterns)
        self.assertIn("HARDCODED_SECRETS_REGEX", self.analyzer.regex_patterns)
    
    def test_supported_languages(self):
        """Testa linguagens suportadas"""
        languages = self.analyzer.get_supported_languages()
        self.assertIn("python", languages)
        self.assertIsInstance(languages, list)
    
    def test_supported_extensions(self):
        """Testa extensões suportadas"""
        extensions = self.analyzer.get_supported_extensions()
        self.assertIn(".py", extensions)
        self.assertIn(".pyw", extensions)
        self.assertIsInstance(extensions, list)
    
    @patch('builtins.open', new_callable=mock_open)
    def test_analyze_complete_flow(self, mock_file):
        """Testa fluxo completo de análise"""
        mock_file.return_value.read.return_value = self.sample_python_code
        
        findings = self.analyzer.analyze("test.py", [], {})
        
        self.assertIsInstance(findings, list)
        # Deve encontrar várias vulnerabilidades no código sample
        self.assertGreater(len(findings), 0)
        
        # Verifica se todos os findings são válidos
        for finding in findings:
            self.assertIsInstance(finding, Finding)
            self.assertIsInstance(finding.severity, Severity)
            self.assertIsNotNone(finding.rule_id)
            self.assertIsNotNone(finding.message)
    
    @patch('builtins.open', new_callable=mock_open)
    def test_regex_analysis(self, mock_file):
        """Testa análise por regex"""
        code_with_secrets = 'password = "secret123"\napi_key = "abc123def456"'
        mock_file.return_value.read.return_value = code_with_secrets
        
        findings = self.analyzer._analyze_with_regex("test.py", code_with_secrets, [])
        
        # Deve encontrar hardcoded secrets
        secret_findings = [f for f in findings if 'SECRET' in f.rule_id]
        self.assertGreater(len(secret_findings), 0)
    
    @patch('builtins.open', new_callable=mock_open)
    def test_ast_analysis(self, mock_file):
        """Testa análise por AST"""
        code_with_eval = 'user_input = input("test")\neval(user_input)'
        mock_file.return_value.read.return_value = code_with_eval
        
        findings = self.analyzer._analyze_with_ast("test.py", code_with_eval, [])
        
        # Deve encontrar uso de eval
        eval_findings = [f for f in findings if 'EVAL' in f.rule_id]
        self.assertGreater(len(eval_findings), 0)
    
    def test_apply_regex_pattern(self):
        """Testa aplicação de padrão regex"""
        lines = ["password = 'secret123'", "normal_line", "api_key = 'abc123'"]
        pattern = r"password\s*=\s*['\"][^'\"]+['\"]"
        rule_config = {
            "severity": Severity.MEDIUM,
            "message": "Test message",
            "category": "test"
        }
        
        findings = self.analyzer._apply_regex_pattern(
            "test.py", lines, pattern, "TEST_RULE", rule_config
        )
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_number, 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
    
    def test_apply_rule_regex_pattern(self):
        """Testa aplicação de padrão regex de regra específica"""
        lines = ["password = 'test123'"]
        
        findings = self.analyzer._apply_rule_regex_pattern(
            "test.py", lines, "password\\s*=", self.mock_rules[0]
        )
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "TEST_RULE_1")
        self.assertEqual(finding.severity, Severity.MEDIUM)
    
    def test_remove_duplicate_findings(self):
        """Testa remoção de findings duplicados"""
        # Cria findings duplicados
        finding1 = Finding(
            file_path="test.py",
            line_number=1,
            rule_id="DUPLICATE_RULE",
            severity=Severity.HIGH,
            message="Test message"
        )
        finding2 = Finding(
            file_path="test.py",
            line_number=1,
            rule_id="DUPLICATE_RULE",
            severity=Severity.HIGH,
            message="Different message"
        )
        finding3 = Finding(
            file_path="test.py",
            line_number=2,
            rule_id="UNIQUE_RULE",
            severity=Severity.LOW,
            message="Unique message"
        )
        
        findings = [finding1, finding2, finding3]
        unique_findings = self.analyzer._remove_duplicate_findings(findings)
        
        # Deve ter apenas 2 findings (duplicata removida)
        self.assertEqual(len(unique_findings), 2)
        
        # Verifica se manteve o primeiro finding de cada grupo
        rule_ids = [f.rule_id for f in unique_findings]
        self.assertIn("DUPLICATE_RULE", rule_ids)
        self.assertIn("UNIQUE_RULE", rule_ids)
    
    @patch('builtins.open', side_effect=FileNotFoundError)
    def test_file_read_error_handling(self, mock_file):
        """Testa tratamento de erro na leitura de arquivo"""
        findings = self.analyzer.analyze("nonexistent.py", [], {})
        
        # Deve retornar lista vazia ou com finding de erro
        self.assertIsInstance(findings, list)
    
    @patch('builtins.open', new_callable=mock_open)
    def test_syntax_error_handling(self, mock_file):
        """Testa tratamento de erro de sintaxe"""
        invalid_code = "def invalid_syntax("
        mock_file.return_value.read.return_value = invalid_code
        
        findings = self.analyzer.analyze("test.py", [], {})
        
        # Deve criar finding de erro de sintaxe
        syntax_errors = [f for f in findings if 'SYNTAX' in f.rule_id]
        self.assertGreater(len(syntax_errors), 0)
    
    def test_validate_config(self):
        """Testa validação de configuração"""
        # Configuração com AST depth muito baixo
        config_low = Mock(python_max_ast_depth=5)
        validation = self.analyzer.validate_config(config_low)
        
        self.assertIn("warnings", validation)
        self.assertTrue(any("muito baixo" in w for w in validation["warnings"]))
        
        # Configuração com AST depth muito alto
        config_high = Mock(python_max_ast_depth=1000)
        validation = self.analyzer.validate_config(config_high)
        
        self.assertTrue(any("muito alto" in w for w in validation["warnings"]))
        
        # Configuração normal
        config_normal = Mock(python_max_ast_depth=100)
        validation = self.analyzer.validate_config(config_normal)
        
        # Não deve ter warnings específicos sobre AST depth
        ast_warnings = [w for w in validation["warnings"] if "ast_depth" in w]
        self.assertEqual(len(ast_warnings), 0)


class TestPythonAnalyzerIntegration(unittest.TestCase):
    """Testes de integração com arquivos reais"""
    
    def setUp(self):
        """Configuração para testes de integração"""
        self.analyzer = PythonAnalyzer()
        self.temp_dir = None
    
    def tearDown(self):
        """Limpeza após testes"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
    
    def create_temp_file(self, content: str, filename: str = "test.py") -> str:
        """Cria arquivo temporário para teste"""
        if not self.temp_dir:
            self.temp_dir = tempfile.mkdtemp()
        
        file_path = os.path.join(self.temp_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return file_path
    
    def test_real_vulnerable_file(self):
        """Testa análise de arquivo vulnerável real"""
        vulnerable_code = '''
import os
import subprocess
from flask import request

# Hardcoded secrets
DB_PASSWORD = "super_secret_123"
API_KEY = "sk-1234567890abcdef"

def dangerous_endpoint():
    # Command injection
    filename = request.args.get('file')
    os.system(f"cat {filename}")
    
    # SQL injection
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    # Dangerous function with user input
    code = request.form.get('code')
    eval(code)
    
    return "Done"

def path_traversal():
    filename = request.args.get('filename')
    with open(f"/uploads/{filename}", 'r') as f:
        return f.read()
'''
        
        file_path = self.create_temp_file(vulnerable_code)
        findings = self.analyzer.analyze(file_path, [], {})
        
        # Deve encontrar múltiplas vulnerabilidades
        self.assertGreater(len(findings), 3)
        
        # Verifica tipos específicos de vulnerabilidades
        finding_types = [f.rule_id for f in findings]
        
        # Deve ter pelo menos alguns tipos esperados
        has_secrets = any("SECRET" in ft or "PASSWORD" in ft for ft in finding_types)
        has_injection = any("INJECTION" in ft for ft in finding_types)
        has_dangerous = any("DANGEROUS" in ft or "EVAL" in ft for ft in finding_types)
        
        self.assertTrue(has_secrets or has_injection or has_dangerous,
                       f"Deveria encontrar vulnerabilidades conhecidas. Findings: {finding_types}")
    
    def test_safe_file(self):
        """Testa análise de arquivo seguro"""
        safe_code = '''
import hashlib
import logging
from typing import Optional

def hash_password(password: str, salt: str) -> str:
    """Safely hash a password with salt"""
    return hashlib.pbkdf2_hmac('sha256', 
                              password.encode('utf-8'), 
                              salt.encode('utf-8'), 
                              100000)

def validate_input(user_input: str) -> Optional[str]:
    """Validate and sanitize user input"""
    if not user_input or len(user_input) > 100:
        return None
    
    # Remove dangerous characters
    safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')
    sanitized = ''.join(c for c in user_input if c in safe_chars)
    
    return sanitized

def safe_database_query(connection, user_id: int):
    """Use parameterized queries"""
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()

def log_action(action: str):
    """Safe logging"""
    logging.info("User action: %s", action)
'''
        
        file_path = self.create_temp_file(safe_code)
        findings = self.analyzer.analyze(file_path, [], {})
        
        # Arquivo seguro deve ter poucos ou nenhum finding de alta severidade
        high_severity = [f for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]
        self.assertEqual(len(high_severity), 0, 
                        f"Arquivo seguro não deveria ter findings de alta severidade: {[f.message for f in high_severity]}")
    
    def test_mixed_content_file(self):
        """Testa arquivo com conteúdo misto (seguro e vulnerável)"""
        mixed_code = '''
import os
import hashlib

# Safe constant
MAX_RETRIES = 3

# Hardcoded secret (vulnerable)
SECRET_KEY = "abc123def456"

def safe_function():
    """This function is safe"""
    return hashlib.sha256(b"safe data").hexdigest()

def vulnerable_function(user_input):
    """This function has vulnerabilities"""
    # Command injection
    os.system("echo " + user_input)
    
    # Dangerous eval
    eval(user_input)

def another_safe_function():
    """Another safe function"""
    print("Safe operation")
'''
        
        file_path = self.create_temp_file(mixed_code)
        findings = self.analyzer.analyze(file_path, [], {})
        
        # Deve encontrar vulnerabilidades apenas nas funções vulneráveis
        self.assertGreater(len(findings), 0)
        
        # Verifica se encontrou tipos específicos
        has_secrets = any("SECRET" in f.rule_id for f in findings)
        has_command_injection = any("COMMAND" in f.rule_id for f in findings)
        has_eval = any("EVAL" in f.rule_id for f in findings)
        
        # Deve encontrar pelo menos algumas vulnerabilidades
        vulnerabilities_found = sum([has_secrets, has_command_injection, has_eval])
        self.assertGreater(vulnerabilities_found, 0)


class TestPythonAnalyzerEdgeCases(unittest.TestCase):
    """Testes para casos extremos e edge cases"""
    
    def setUp(self):
        self.analyzer = PythonAnalyzer()
    
    @patch('builtins.open', new_callable=mock_open)
    def test_empty_file(self, mock_file):
        """Testa análise de arquivo vazio"""
        mock_file.return_value.read.return_value = ""
        
        findings = self.analyzer.analyze("empty.py", [], {})
        self.assertIsInstance(findings, list)
        # Arquivo vazio não deve gerar findings de vulnerabilidade
        vulnerability_findings = [f for f in findings if f.severity != Severity.INFO]
        self.assertEqual(len(vulnerability_findings), 0)
    
    @patch('builtins.open', new_callable=mock_open)
    def test_very_large_file(self, mock_file):
        """Testa análise de arquivo muito grande"""
        # Simula arquivo grande
        large_content = "print('safe line')\n" * 10000
        mock_file.return_value.read.return_value = large_content
        
        findings = self.analyzer.analyze("large.py", [], {})
        self.assertIsInstance(findings, list)
        # Não deve falhar com arquivo grande
    
    @patch('builtins.open', new_callable=mock_open)
    def test_unicode_content(self, mock_file):
        """Testa análise de arquivo com Unicode"""
        unicode_content = '''
# -*- coding: utf-8 -*-
password = "señorita123"  # Conteúdo com acentos
api_key = "chave_çom_ç_e_ñ"
print("Olá, mundo! 🌍")
'''
        mock_file.return_value.read.return_value = unicode_content
        
        findings = self.analyzer.analyze("unicode.py", [], {})
        self.assertIsInstance(findings, list)
        # Deve encontrar hardcoded secrets mesmo com Unicode
        secret_findings = [f for f in findings if 'SECRET' in f.rule_id or 'PASSWORD' in f.rule_id]
        self.assertGreater(len(secret_findings), 0)
    
    @patch('builtins.open', new_callable=mock_open)
    def test_complex_ast_structure(self, mock_file):
        """Testa análise de estrutura AST complexa"""
        complex_code = '''
class ComplexClass:
    def __init__(self):
        self.password = "secret123"  # Hardcoded
    
    def method_with_nested_calls(self):
        result = self.get_data(
            lambda x: eval(x) if x else None,  # Dangerous eval
            {
                'query': "SELECT * FROM " + table_name,  # SQL injection
                'command': os.system("ls " + directory)  # Command injection
            }
        )
        return result
    
    @staticmethod
    def static_method():
        exec(compile(user_code, '<string>', 'exec'))  # Multiple dangerous calls
'''
        mock_file.return_value.read.return_value = complex_code
        
        findings = self.analyzer.analyze("complex.py", [], {})
        self.assertIsInstance(findings, list)
        # Deve encontrar vulnerabilidades em estruturas complexas
        self.assertGreater(len(findings), 2)
    
    @patch('builtins.open', new_callable=mock_open)
    def test_false_positives_reduction(self, mock_file):
        """Testa redução de falsos positivos"""
        code_with_safe_patterns = '''
# Safe uses that might trigger false positives
import subprocess

def safe_subprocess_usage():
    # Safe: hardcoded command
    subprocess.run(["ls", "-la"], shell=False)
    
def safe_eval_usage():
    # Safe: eval with literal
    result = eval("2 + 2")
    
def safe_execute_usage():
    # Safe: parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Comments that mention dangerous things should not trigger
# "password = secret" in comments
# eval(malicious_code) in documentation

def documented_function():
    """
    This function is safe.
    Do not use eval() or os.system() here.
    Password should not be hardcoded.
    """
    pass
'''
        mock_file.return_value.read.return_value = code_with_safe_patterns
        
        findings = self.analyzer.analyze("safe_patterns.py", [], {})
        
        # Deve ter poucos ou nenhum finding de alta severidade
        high_severity = [f for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]
        
        # Aceita alguns findings, mas não muitos falsos positivos
        self.assertLessEqual(len(high_severity), 2, 
                           f"Muitos falsos positivos detectados: {[f.message for f in high_severity]}")


if __name__ == '__main__':
    # Configuração de logging para testes
    import logging
    logging.basicConfig(level=logging.WARNING)
    
    # Executa todos os testes
    unittest.main(verbosity=2)