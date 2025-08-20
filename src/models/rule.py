from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
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
    
    def __post_init__(self):
        """Validações após inicialização"""
        if not self.id:
            raise ValueError("Rule ID é obrigatório")
        if not self.patterns:
            raise ValueError("Rule deve ter pelo menos um pattern")
        
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
    """Engine para gerenciar regras - SEM lógica de carregamento duplicada"""
    
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
    
    def load_builtin_rules(self) -> int:
        """
        Carrega regras padrão usando RuleLoader
        """
        try:
            from ..utils.rule_loader import RuleLoader
            loader = RuleLoader()
            rules = loader.load_builtin_rules()
            
            loaded_count = 0
            for rule in rules:
                self.add_rule(rule)
                loaded_count += 1
            
            return loaded_count
            
        except Exception as e:
            print(f"❌ Erro ao carregar regras padrão: {e}")
            return 0
    
    # Refatorado --> Agora utilizando apenas o rule_loader
    def load_rules_from_directory(self, directory_path: Optional[str] = None) -> int:
        try:
            from ..utils.rule_loader import RuleLoader
            loader = RuleLoader(directory_path)
            rules = loader.load_rules_from_directory()
            
            loaded_count = 0
            for rule in rules:
                self.add_rule(rule)
                loaded_count += 1
            
            return loaded_count
            
        except ImportError:
            # Fallback se RuleLoader não estiver disponível
            print("⚠️  RuleLoader não disponível, usando carregamento básico")
            return self._load_rules_basic(directory_path or "src/rules")
        except Exception as e:
            print(f"❌ Erro ao carregar regras: {e}")
            return 0
    
    # Fallback caso o rule_loader não funcione
    def _load_rules_basic(self, directory_path: str) -> int:
        """Método de fallback (carregamento básico)"""
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
    
    def save_rules(self, directory_path: str, format_type: str = "json") -> int:
        """
        Salva regras usando RuleLoader
        """
        try:
            from ..utils.rule_loader import RuleLoader
            loader = RuleLoader()
            rules_list = list(self.rules.values())
            
            success = loader.save_rules_to_directory(
                rules_list, 
                directory_path, 
                format_type
            )
            
            return len(rules_list) if success else 0
            
        except Exception as e:
            print(f"❌ Erro ao salvar regras: {e}")
            return 0
    
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


# Factory functions simplificadas
def create_rule_from_dict(rule_data: Dict[str, Any]) -> Rule:
    """Factory function genérica para criar regra a partir de dicionário"""
    return Rule.from_dict(rule_data)


def create_engine_with_default_rules() -> RuleEngine:
    """
    Cria RuleEngine com regras padrão carregadas
    """
    engine = RuleEngine()
    engine.load_builtin_rules()
    return engine

#engine = create_engine_with_default_rules()