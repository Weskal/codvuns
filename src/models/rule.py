from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any, Callable
import json
from pathlib import Path

from .finding import Severity


class RuleType(Enum):
    """Tipos de regras suportadas"""
    REGEX = "regex"                    # Busca por padrões regex
    AST = "ast"                       # Análise de AST (Python)
    PATTERN = "pattern"               # Padrões específicos de linguagem
    SEMANTIC = "semantic"             # Análise semântica
    CONFIGURATION = "configuration"  # Arquivos de configuração


class VulnerabilityCategory(Enum):
    """Categorias de vulnerabilidades (baseado em OWASP Top 10)"""
    INJECTION = "injection"                           # SQL, NoSQL, Command Injection
    BROKEN_AUTHENTICATION = "broken_authentication"  # Autenticação quebrada
    SENSITIVE_DATA = "sensitive_data"                # Exposição de dados sensíveis
    XXE = "xxe"                                      # XML External Entities
    BROKEN_ACCESS_CONTROL = "broken_access_control" # Controle de acesso quebrado
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    XSS = "xss"                                      # Cross-Site Scripting
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    LOGGING_MONITORING = "logging_monitoring"
    
    # Categorias adicionais
    HARDCODED_SECRETS = "hardcoded_secrets"
    DANGEROUS_FUNCTIONS = "dangerous_functions"
    CRYPTOGRAPHY = "cryptography"


@dataclass
class RuleMatch:
    """Representa um match encontrado por uma regra"""
    start_line: int
    end_line: int
    start_column: int = 0
    end_column: int = 0
    matched_text: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0  # 0.0 a 1.0


@dataclass
class RuleMetadata:
    """Metadados da regra"""
    cwe_id: Optional[str] = None          # Common Weakness Enumeration
    owasp_category: Optional[str] = None  # OWASP Top 10
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    author: Optional[str] = None
    created_date: Optional[str] = None
    last_updated: Optional[str] = None


@dataclass
class Rule:
    """
    Representa uma regra de detecção de vulnerabilidade
    MODELO DE DADOS PURO - sem lógica de análise
    """
    # Identificação
    id: str
    name: str
    description: str
    
    # Classificação
    severity: Severity
    category: VulnerabilityCategory
    
    # Configuração de detecção
    rule_type: RuleType
    patterns: List[str] = field(default_factory=list)  # Regex patterns ou AST patterns
    
    # Filtros
    target_languages: List[str] = field(default_factory=list)
    file_patterns: List[str] = field(default_factory=list)  # *.py, *.js, etc
    excluded_paths: List[str] = field(default_factory=list)
    
    # Configurações avançadas
    case_sensitive: bool = True
    multiline: bool = False
    enabled: bool = True
    confidence_threshold: float = 0.5
    
    # Metadados
    metadata: RuleMetadata = field(default_factory=RuleMetadata)
    
    # Função customizada de análise (opcional)
    custom_analyzer: Optional[Callable] = field(default=None, repr=False)
    
    def __post_init__(self):
        """Validações após inicialização"""
        if not self.id:
            raise ValueError("Rule ID é obrigatório")
        if not self.patterns and not self.custom_analyzer:
            raise ValueError("Rule deve ter patterns ou custom_analyzer")
        
        # Converte strings para enums se necessário
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.upper())
        if isinstance(self.category, str):
            self.category = VulnerabilityCategory(self.category.lower())
        if isinstance(self.rule_type, str):
            self.rule_type = RuleType(self.rule_type.lower())
    
    def matches_file(self, file_path: str, file_language: str) -> bool:
        """Verifica se a regra se aplica a este arquivo"""
        # Verifica se está habilitada
        if not self.enabled:
            return False
        
        # Verifica linguagem
        if self.target_languages and file_language not in self.target_languages:
            return False
        
        # Verifica padrões de arquivo
        if self.file_patterns:
            path_obj = Path(file_path)
            matches_pattern = any(
                path_obj.match(pattern) for pattern in self.file_patterns
            )
            if not matches_pattern:
                return False
        
        # Verifica caminhos excluídos
        for excluded in self.excluded_paths:
            if excluded in file_path:
                return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte regra para dicionário"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity.value,
            'category': self.category.value,
            'rule_type': self.rule_type.value,
            'patterns': self.patterns,
            'target_languages': self.target_languages,
            'file_patterns': self.file_patterns,
            'excluded_paths': self.excluded_paths,
            'case_sensitive': self.case_sensitive,
            'multiline': self.multiline,
            'enabled': self.enabled,
            'confidence_threshold': self.confidence_threshold,
            'metadata': {
                'cwe_id': self.metadata.cwe_id,
                'owasp_category': self.metadata.owasp_category,
                'references': self.metadata.references,
                'tags': self.metadata.tags,
                'author': self.metadata.author,
                'created_date': self.metadata.created_date,
                'last_updated': self.metadata.last_updated
            }
        }
    
    def to_json(self) -> str:
        """Serializa regra para JSON"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Rule':
        """Cria regra a partir de dicionário"""
        # Extrai metadados se existirem
        metadata_data = data.pop('metadata', {})
        metadata = RuleMetadata(**metadata_data)
        
        return cls(metadata=metadata, **data)


class RuleEngine:
    """Engine para gerenciar regras - SEM lógica de análise"""
    
    def __init__(self):
        self.rules: Dict[str, Rule] = {}
        self.enabled_categories: List[VulnerabilityCategory] = list(VulnerabilityCategory)
    
    def add_rule(self, rule: Rule) -> None:
        """Adiciona uma regra ao engine"""
        self.rules[rule.id] = rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove uma regra do engine"""
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Obtém uma regra por ID"""
        return self.rules.get(rule_id)
    
    def get_rules_by_category(self, category: VulnerabilityCategory) -> List[Rule]:
        """Obtém regras por categoria"""
        return [rule for rule in self.rules.values() if rule.category == category]
    
    def get_rules_for_file(self, file_path: str, file_language: str) -> List[Rule]:
        """Obtém regras aplicáveis a um arquivo específico"""
        applicable_rules = []
        for rule in self.rules.values():
            if (rule.enabled and 
                rule.category in self.enabled_categories and
                rule.matches_file(file_path, file_language)):
                applicable_rules.append(rule)
        
        return applicable_rules
    
    def load_rules_from_directory(self, directory_path: str) -> int:
        """Carrega regras de arquivos YAML/JSON em um diretório"""
        loaded_count = 0
        directory = Path(directory_path)
        
        if not directory.exists():
            return 0
        
        for file_path in directory.glob("*.json"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    rule_data = json.load(f)
                    
                    # Suporta lista de regras ou regra única
                    if isinstance(rule_data, list):
                        rules_list = rule_data
                    else:
                        rules_list = [rule_data]
                    
                    for rule_dict in rules_list:
                        rule = Rule.from_dict(rule_dict)
                        self.add_rule(rule)
                        loaded_count += 1
                        
            except Exception as e:
                print(f"Erro ao carregar regra de {file_path}: {e}")
        
        return loaded_count
    
    def export_rules_to_directory(self, directory_path: str) -> int:
        """Exporta regras para arquivos JSON"""
        directory = Path(directory_path)
        directory.mkdir(exist_ok=True)
        
        exported_count = 0
        for rule in self.rules.values():
            file_path = directory / f"{rule.id}.json"
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(rule.to_json())
                exported_count += 1
            except Exception as e:
                print(f"Erro ao exportar regra {rule.id}: {e}")
        
        return exported_count
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtém estatísticas das regras"""
        total_rules = len(self.rules)
        enabled_rules = sum(1 for rule in self.rules.values() if rule.enabled)
        
        category_stats = {}
        severity_stats = {}
        type_stats = {}
        
        for rule in self.rules.values():
            # Por categoria
            cat = rule.category.value
            category_stats[cat] = category_stats.get(cat, 0) + 1
            
            # Por severidade
            sev = rule.severity.value
            severity_stats[sev] = severity_stats.get(sev, 0) + 1
            
            # Por tipo
            typ = rule.rule_type.value
            type_stats[typ] = type_stats.get(typ, 0) + 1
        
        return {
            'total_rules': total_rules,
            'enabled_rules': enabled_rules,
            'disabled_rules': total_rules - enabled_rules,
            'by_category': category_stats,
            'by_severity': severity_stats,
            'by_type': type_stats
        }


# Factory functions para criar regras comuns (REMOVIDAS - agora estão em JSON)
# Essas funções foram movidas para src/rules/example_rules.json para maior flexibilidade

def create_rule_from_dict(rule_data: Dict[str, Any]) -> Rule:
    """Factory function genérica para criar regra a partir de dicionário"""
    return Rule.from_dict(rule_data)


def create_default_ruleset() -> List[Rule]:
    """
    Carrega conjunto padrão de regras do arquivo JSON
    DEPRECATED: Use RuleLoader.load_builtin_rules() instead
    """
    import json
    from pathlib import Path
    
    # Localiza arquivo de regras padrão
    current_dir = Path(__file__).parent
    rules_file = current_dir.parent / "rules" / "example_rules.json"
    
    if not rules_file.exists():
        print(f"⚠️  Arquivo de regras não encontrado: {rules_file}")
        return []
    
    try:
        with open(rules_file, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
        
        rules = []
        for rule_data in rules_data:
            try:
                rule = Rule.from_dict(rule_data)
                rules.append(rule)
            except Exception as e:
                print(f"⚠️  Erro ao carregar regra {rule_data.get('id', 'unknown')}: {e}")
        
        return rules
        
    except Exception as e:
        print(f"❌ Erro ao carregar regras padrão: {e}")
        return []
    
def get_rule(self, rule_id: str) -> Optional[Rule]:
    """Obtém uma regra por ID"""
    return self.rules.get(rule_id)

def get_rules_by_category(self, category: VulnerabilityCategory) -> List[Rule]:
    """Obtém regras por categoria"""
    return [rule for rule in self.rules.values() if rule.category == category]

def get_rules_for_file(self, file_path: str, file_language: str) -> List[Rule]:
    """Obtém regras aplicáveis a um arquivo específico"""
    applicable_rules = []
    for rule in self.rules.values():
        if (rule.enabled and 
            rule.category in self.enabled_categories and
            rule.matches_file(file_path, file_language)):
            applicable_rules.append(rule)
    
    return applicable_rules

def analyze_file_content(self, content: str, file_path: str, 
                        file_language: str) -> Dict[str, List[RuleMatch]]:
    """Analisa conteúdo de arquivo com todas as regras aplicáveis"""
    results = {}
    applicable_rules = self.get_rules_for_file(file_path, file_language)
    
    for rule in applicable_rules:
        matches = rule.analyze_content(content, file_path)
        if matches:
            results[rule.id] = matches
    
    return results

def load_rules_from_directory(self, directory_path: str) -> int:
    """Carrega regras de arquivos YAML/JSON em um diretório"""
    loaded_count = 0
    directory = Path(directory_path)
    
    if not directory.exists():
        return 0
    
    for file_path in directory.glob("*.yaml"):
        try:
            # Implementar carregamento YAML aqui
            pass
        except Exception as e:
            print(f"Erro ao carregar regra de {file_path}: {e}")
    
    for file_path in directory.glob("*.json"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = json.load(f)
                rule = Rule.from_dict(rule_data)
                self.add_rule(rule)
                loaded_count += 1
        except Exception as e:
            print(f"Erro ao carregar regra de {file_path}: {e}")
    
    return loaded_count

def export_rules_to_directory(self, directory_path: str) -> int:
    """Exporta regras para arquivos JSON"""
    directory = Path(directory_path)
    directory.mkdir(exist_ok=True)
    
    exported_count = 0
    for rule in self.rules.values():
        file_path = directory / f"{rule.id}.json"
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(rule.to_json())
            exported_count += 1
        except Exception as e:
            print(f"Erro ao exportar regra {rule.id}: {e}")
    
    return exported_count

def get_stats(self) -> Dict[str, Any]:
    """Obtém estatísticas das regras"""
    total_rules = len(self.rules)
    enabled_rules = sum(1 for rule in self.rules.values() if rule.enabled)
    
    category_stats = {}
    severity_stats = {}
    type_stats = {}
    
    for rule in self.rules.values():
        # Por categoria
        cat = rule.category.value
        category_stats[cat] = category_stats.get(cat, 0) + 1
        
        # Por severidade
        sev = rule.severity.value
        severity_stats[sev] = severity_stats.get(sev, 0) + 1
        
        # Por tipo
        typ = rule.rule_type.value
        type_stats[typ] = type_stats.get(typ, 0) + 1
    
    return {
        'total_rules': total_rules,
        'enabled_rules': enabled_rules,
        'disabled_rules': total_rules - enabled_rules,
        'by_category': category_stats,
        'by_severity': severity_stats,
        'by_type': type_stats
    }

