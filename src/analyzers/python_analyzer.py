import ast
import re
from typing import List, Dict, Any, Optional, Set, Union
from pathlib import Path
import logging

from .base_analyzer import BaseAnalyzer
from ..models.finding import Finding, Severity


class PythonASTVisitor(ast.NodeVisitor):
    """
    Visitor personalizado para analisar árvore AST Python.
    
    Percorre todos os nós da AST procurando por padrões perigosos
    e vulnerabilidades de segurança específicas do Python.
    """
    
    def __init__(self, file_path: str, content: str):
        self.file_path = file_path
        self.content = content
        self.findings: List[Finding] = []
        self.lines = content.splitlines()
        
        # Conjuntos de funções/módulos perigosos
        self.dangerous_functions = {
            'eval', 'exec', 'compile', '__import__'
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
        """Visita chamadas de função"""
        try:
            func_name = self._get_function_name(node.func)
            line_number = getattr(node, 'lineno', 0)
            
            # Detecta funções perigosas
            if func_name in self.dangerous_functions:
                self._create_dangerous_function_finding(node, func_name, line_number)
            
            # Detecta calls de sistema perigosos
            elif func_name in self.dangerous_modules:
                self._create_command_injection_finding(node, func_name, line_number)
            
            # Detecta SQL injection potencial
            elif any(sql_func in func_name for sql_func in self.sql_functions):
                self._check_sql_injection(node, func_name, line_number)
            
            # Detecta input do usuário (marca variáveis como tainted)
            elif func_name in self.user_input_functions:
                self._mark_user_input(node, line_number)
            
        except Exception as e:
            logging.warning(f"Erro ao analisar call em {self.file_path}:{line_number}: {e}")
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Visita atribuições de variáveis"""
        try:
            line_number = getattr(node, 'lineno', 0)
            
            # Propaga taint através de atribuições
            if isinstance(node.value, ast.Call):
                func_name = self._get_function_name(node.value.func)
                if func_name in self.user_input_functions:
                    # Marca variáveis que recebem input do usuário
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_vars.add(target.id)
            
            # Verifica se atribuição envolve concatenação com dados tainted
            elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                # Se concatena com dados tainted, propaga o taint
                if self._binop_uses_tainted(node.value):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.tainted_vars.add(target.id)
            
            # Verifica hardcoded secrets em atribuições
            self._check_hardcoded_secrets(node)
            
        except Exception as e:
            line_number = getattr(node, 'lineno', 0)
            logging.warning(f"Erro ao analisar assign em {self.file_path}:{line_number}: {e}")
        
        self.generic_visit(node)
    
    def visit_Str(self, node: ast.Str) -> None:
        """Visita strings literais (Python < 3.8)"""
        self._check_string_content(node.s, getattr(node, 'lineno', 0))
        self.generic_visit(node)
    
    def visit_Constant(self, node: ast.Constant) -> None:
        """Visita constantes (Python >= 3.8)"""
        if isinstance(node.value, str):
            self._check_string_content(node.value, getattr(node, 'lineno', 0))
        self.generic_visit(node)
    
    def _get_function_name(self, func_node: ast.AST) -> str:
        """Extrai nome da função de diferentes tipos de nós"""
        try:
            if isinstance(func_node, ast.Name):
                return func_node.id
            elif isinstance(func_node, ast.Attribute):
                # Para calls como os.system, request.form
                if isinstance(func_node.value, ast.Name):
                    return f"{func_node.value.id}.{func_node.attr}"
                elif isinstance(func_node.value, ast.Attribute):
                    # Para casos aninhados como request.args.get
                    parent = self._get_function_name(func_node.value)
                    return f"{parent}.{func_node.attr}"
                else:
                    return f"unknown.{func_node.attr}"
            elif isinstance(func_node, ast.Call):
                return self._get_function_name(func_node.func)
            else:
                return 'unknown'
        except Exception as e:
            logging.warning(f"Erro ao extrair nome da função: {e}")
            return 'unknown'
    
    def _create_dangerous_function_finding(self, node: ast.Call, func_name: str, line_number: int) -> None:
        """Cria finding para funções perigosas"""
        line_content = self._get_line_content(line_number)
        
        # Verifica se usa dados tainted
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
        
        # Verifica se usa dados tainted
        severity = Severity.MEDIUM
        if self._uses_tainted_data(node):
            severity = Severity.CRITICAL
        
        finding = Finding(
            file_path=self.file_path,
            line_number=line_number,
            rule_id="COMMAND_INJECTION_001",
            severity=severity,
            message=f"Potencial command injection em '{func_name}'",
            code_snippet=line_content,
            category="injection"
        )
        self.findings.append(finding)
    
    def _check_sql_injection(self, node: ast.Call, func_name: str, line_number: int) -> None:
        """Verifica SQL injection em queries"""
        line_content = self._get_line_content(line_number)
        
        # Verifica se há concatenação de strings na query ou uso de dados tainted
        has_concatenation = self._has_string_concatenation(node)
        uses_tainted = self._uses_tainted_data(node)
        
        # Verifica se a linha contém padrões suspeitos
        line_has_concat = '+' in line_content and any(sql_word in line_content.upper() for sql_word in ['SELECT', 'INSERT', 'UPDATE', 'DELETE'])
        
        if has_concatenation or uses_tainted or line_has_concat:
            severity = Severity.CRITICAL if uses_tainted else Severity.HIGH
            finding = Finding(
                file_path=self.file_path,
                line_number=line_number,
                rule_id="SQL_INJECTION_001",
                severity=severity,
                message=f"Potencial SQL injection em '{func_name}' - uso de concatenação ou dados não confiáveis",
                code_snippet=line_content,
                category="injection"
            )
            self.findings.append(finding)
    
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
            
            # Verifica nomes de variáveis
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    for pattern in secret_patterns:
                        if re.search(pattern, var_name):
                            # Verifica se atribui string literal
                            if isinstance(node.value, (ast.Str, ast.Constant)):
                                value = node.value.s if isinstance(node.value, ast.Str) else node.value.value
                                if isinstance(value, str) and len(value) > 3:
                                    finding = Finding(
                                        file_path=self.file_path,
                                        line_number=line_number,
                                        rule_id="HARDCODED_SECRET_001",
                                        severity=Severity.HIGH,
                                        message=f"Possível hardcoded secret na variável '{var_name}'",
                                        code_snippet=line_content,
                                        category="hardcoded_secrets"
                                    )
                                    self.findings.append(finding)
                                    break
        except Exception as e:
            logging.warning(f"Erro ao verificar hardcoded secrets: {e}")
    
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
                        message=f"Possível {secret_type.lower()} hardcoded detectado",
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
                elif isinstance(arg, ast.BinOp):  # Concatenação
                    return self._binop_uses_tainted(arg)
            return False
        except:
            return False
    
    def _has_string_concatenation(self, node: ast.Call) -> bool:
        """Verifica se há concatenação de strings nos argumentos"""
        try:
            # Verifica argumentos diretos
            for arg in node.args:
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    # Verifica se pelo menos um lado é string
                    if (isinstance(arg.left, (ast.Str, ast.Constant)) or 
                        isinstance(arg.right, (ast.Str, ast.Constant)) or
                        isinstance(arg.left, ast.Name) or isinstance(arg.right, ast.Name)):
                        return True
                elif isinstance(arg, ast.Name):
                    # Verifica se a variável pode ter sido criada por concatenação
                    # Busca pela linha anterior ou contexto
                    continue
            
            # Verifica keywords arguments também
            for keyword in getattr(node, 'keywords', []):
                if isinstance(keyword.value, ast.BinOp) and isinstance(keyword.value.op, ast.Add):
                    return True
                    
            return False
        except Exception as e:
            logging.warning(f"Erro ao verificar concatenação: {e}")
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
    
    def _mark_user_input(self, node: ast.Call, line_number: int) -> None:
        """Marca que foi detectado input do usuário e propaga taint"""
        try:
            # Encontra qual variável recebe o input olhando o contexto
            # Isso requer análise do nó pai (assignment)
            
            # Para casos como: user_input = input("...")
            # Nota: Esta é uma implementação básica
            # Uma implementação completa precisaria de análise mais sofisticada
            
            line_content = self._get_line_content(line_number)
            
            # Busca padrão de atribuição na linha
            import re
            assignment_match = re.match(r'\s*(\w+)\s*=\s*input\s*\(', line_content)
            if assignment_match:
                var_name = assignment_match.group(1)
                self.tainted_vars.add(var_name)
                logging.debug(f"Marcando variável '{var_name}' como tainted")
                
        except Exception as e:
            logging.warning(f"Erro ao marcar user input: {e}")
    
    def _get_line_content(self, line_number: int) -> str:
        """Obtém conteúdo de uma linha específica"""
        try:
            if 1 <= line_number <= len(self.lines):
                return self.lines[line_number - 1].strip()
            return ""
        except:
            return ""


class PythonAnalyzer(BaseAnalyzer):
    """
    Analyzer específico para código Python.
    
    Combina análise regex (rápida) com análise AST (profunda) para
    detectar vulnerabilidades de segurança em código Python.
    """
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        
        # Padrões regex para detecção rápida
        self.regex_patterns = {
            "SQL_INJECTION_REGEX": {
                "patterns": [
                    r'(?:execute|query)\s*\(\s*["\'][^"\']*["\']?\s*\+',
                    r'(?:execute|query)\s*\(\s*f["\'][^"\']*\{[^}]+\}',
                    r'cursor\.execute\s*\(\s*["\'][^"\']*["\']?\s*\+',
                    r'cursor\.execute\s*\(\s*[^"\']*\+',  # Detecta execute com concatenação
                    r'SELECT\s+.*\+.*FROM',
                    r'INSERT\s+.*\+.*VALUES',
                    r'UPDATE\s+.*SET.*\+',
                    r'DELETE\s+.*WHERE.*\+'
                ],
                "severity": Severity.HIGH,
                "message": "Possível SQL injection detectado via regex",
                "category": "injection"
            },
            "COMMAND_INJECTION_REGEX": {
                "patterns": [
                    r'os\.system\s*\(\s*["\'][^"\']*["\']?\s*\+',
                    r'subprocess\.(call|run|Popen)\s*\(\s*["\'][^"\']*["\']?\s*\+',
                    r'os\.popen\s*\(\s*["\'][^"\']*["\']?\s*\+',
                    r'shell=True.*\+'
                ],
                "severity": Severity.CRITICAL,
                "message": "Possível command injection detectado via regex",
                "category": "injection"
            },
            "HARDCODED_SECRETS_REGEX": {
                "patterns": [
                    r'(?i)password\s*=\s*["\'][^"\']{6,}["\']',
                    r'(?i)api[_-]?key\s*=\s*["\'][^"\']{10,}["\']',
                    r'(?i)secret[_-]?key\s*=\s*["\'][^"\']{10,}["\']',
                    r'(?i)token\s*=\s*["\'][^"\']{20,}["\']',
                    r'(?i)auth[_-]?token\s*=\s*["\'][^"\']{15,}["\']'
                ],
                "severity": Severity.MEDIUM,
                "message": "Possível credencial hardcoded detectada via regex",
                "category": "hardcoded_secrets"
            }
        }
    
    def get_supported_languages(self) -> List[str]:
        """Retorna linguagens suportadas"""
        return ["python"]
    
    def get_supported_extensions(self) -> List[str]:
        """Retorna extensões de arquivo suportadas"""
        return [".py", ".pyw"]
    
    def analyze(self, file_path: str, rules: List, config: Any) -> List[Finding]:
        """
        Executa análise completa do arquivo Python.
        
        Combina análise regex (rápida) e AST (profunda) para máxima cobertura.
        
        Args:
            file_path: Caminho do arquivo Python
            rules: Lista de regras aplicáveis
            config: Configurações de análise
            
        Returns:
            Lista de vulnerabilidades encontradas
        """
        findings = []
        
        try:
            # Lê conteúdo do arquivo
            content = self.read_files(file_path)
            if not content:
                self.logger.warning(f"Não foi possível ler arquivo: {file_path}")
                return findings
            
            self.logger.debug(f"Analisando arquivo Python: {file_path}")
            
            # 1. Análise Regex (rápida)
            regex_findings = self._analyze_with_regex(file_path, content, rules)
            findings.extend(regex_findings)
            
            # 2. Análise AST (profunda)
            ast_findings = self._analyze_with_ast(file_path, content, rules)
            findings.extend(ast_findings)
            
            # 3. Remove duplicatas (mesmo line_number + rule_id)
            findings = self._remove_duplicate_findings(findings)
            
            self.logger.info(f"Análise concluída: {len(findings)} vulnerabilidades encontradas em {file_path}")
            
        except Exception as e:
            self.logger.error(f"Erro durante análise de {file_path}: {e}")
            
            # Cria finding de erro para tracking
            error_finding = Finding(
                file_path=file_path,
                line_number=1,
                rule_id="ANALYSIS_ERROR",
                severity=Severity.INFO,
                message=f"Erro durante análise: {str(e)}",
                category="error"
            )
            findings.append(error_finding)
        
        return findings
    
    def _analyze_with_regex(self, file_path: str, content: str, rules: List) -> List[Finding]:
        """Executa análise baseada em regex"""
        findings = []
        lines = content.splitlines()
        
        try:
            # Aplica padrões regex próprios do analyzer
            for rule_id, rule_config in self.regex_patterns.items():
                for pattern in rule_config["patterns"]:
                    findings.extend(self._apply_regex_pattern(
                        file_path, lines, pattern, rule_id, rule_config
                    ))
            
            # Aplica regras regex das configurações
            applicable_rules = self.filter_applicable_rules(rules, file_path)
            for rule in applicable_rules:
                if hasattr(rule, 'rule_type') and rule.rule_type.value == 'regex':
                    for pattern in rule.patterns:
                        findings.extend(self._apply_rule_regex_pattern(
                            file_path, lines, pattern, rule
                        ))
                        
        except Exception as e:
            self.logger.warning(f"Erro na análise regex de {file_path}: {e}")
        
        return findings
    
    def _apply_regex_pattern(self, file_path: str, lines: List[str], pattern: str, 
                           rule_id: str, rule_config: Dict) -> List[Finding]:
        """Aplica um padrão regex específico"""
        findings = []
        
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for line_num, line in enumerate(lines, 1):
                matches = compiled_pattern.finditer(line)
                for match in matches:
                    finding = Finding(
                        file_path=file_path,
                        line_number=line_num,
                        rule_id=rule_id,
                        severity=rule_config["severity"],
                        message=rule_config["message"],
                        code_snippet=line.strip(),
                        category=rule_config.get("category", "unknown"),
                        column=match.start() + 1
                    )
                    findings.append(finding)
                    self.logger.debug(f"Regex match: {rule_id} na linha {line_num}")
                    
        except re.error as e:
            self.logger.warning(f"Erro no padrão regex '{pattern}': {e}")
        except Exception as e:
            self.logger.warning(f"Erro ao aplicar regex: {e}")
        
        return findings
    
    def _apply_rule_regex_pattern(self, file_path: str, lines: List[str], 
                                pattern: str, rule) -> List[Finding]:
        """Aplica padrão regex de uma regra específica"""
        findings = []
        
        try:
            flags = re.IGNORECASE if not rule.case_sensitive else 0
            if rule.multiline:
                flags |= re.MULTILINE
            
            compiled_pattern = re.compile(pattern, flags)
            
            for line_num, line in enumerate(lines, 1):
                matches = compiled_pattern.finditer(line)
                for match in matches:
                    finding = Finding(
                        file_path=file_path,
                        line_number=line_num,
                        rule_id=rule.id,
                        severity=rule.severity,
                        message=rule.description,
                        code_snippet=line.strip(),
                        category=rule.category.value if hasattr(rule.category, 'value') else str(rule.category),
                        column=match.start() + 1,
                        confidence=getattr(rule, 'confidence_threshold', 0.5)
                    )
                    findings.append(finding)
                    
        except Exception as e:
            self.logger.warning(f"Erro ao aplicar regra regex {rule.id}: {e}")
        
        return findings
    
    def _analyze_with_ast(self, file_path: str, content: str, rules: List) -> List[Finding]:
        """Executa análise baseada em AST"""
        findings = []
        
        try:
            # Parse do código Python para AST
            tree = ast.parse(content, filename=file_path)
            
            # Cria visitor personalizado
            visitor = PythonASTVisitor(file_path, content)
            
            # Percorre a árvore AST
            visitor.visit(tree)
            
            # Coleta findings do visitor
            findings.extend(visitor.findings)
            
            self.logger.debug(f"AST analysis encontrou {len(visitor.findings)} findings")
            
        except SyntaxError as e:
            self.logger.warning(f"Erro de sintaxe em {file_path}: {e}")
            # Arquivo com erro de sintaxe - não consegue analisar via AST
            syntax_finding = Finding(
                file_path=file_path,
                line_number=getattr(e, 'lineno', 1),
                rule_id="SYNTAX_ERROR",
                severity=Severity.LOW,
                message=f"Erro de sintaxe impede análise AST: {e.msg}",
                category="syntax"
            )
            findings.append(syntax_finding)
            
        except Exception as e:
            self.logger.error(f"Erro na análise AST de {file_path}: {e}")
        
        return findings
    
    def _remove_duplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove findings duplicados baseado em linha e rule_id"""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.rule_id)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
            else:
                self.logger.debug(f"Finding duplicado removido: {key}")
        
        return unique_findings
    
    def validate_config(self, config: Any) -> Dict[str, Any]:
        """Valida configurações específicas do PythonAnalyzer"""
        validation = super().validate_config(config)
        warnings = validation["warnings"]
        
        # Validações específicas para Python
        max_ast_depth = getattr(config, 'python_max_ast_depth', 100)
        if max_ast_depth < 10:
            warnings.append("python_max_ast_depth muito baixo, pode afetar detecção")
        elif max_ast_depth > 500:
            warnings.append("python_max_ast_depth muito alto, pode causar lentidão")
        
        validation["warnings"] = warnings
        return validation