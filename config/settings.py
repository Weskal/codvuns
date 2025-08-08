import json
import os
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field


@dataclass
class AnalysisConfig:
    """Configurações específicas para análise"""
    max_file_size_mb: float = 10.0
    max_depth: int = 10
    timeout_seconds: int = 300
    parallel_analysis: bool = True
    max_workers: int = 4


@dataclass
class ReportConfig:
    """Configurações para geração de relatórios"""
    default_format: str = "console"
    include_code_snippets: bool = True
    max_snippet_lines: int = 5
    show_file_stats: bool = True
    color_output: bool = True


@dataclass
class RulesConfig:
    """Configurações das regras de análise"""
    enabled_severities: List[str] = field(default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    disabled_rules: List[str] = field(default_factory=list)
    custom_rules_path: Optional[str] = None
    min_confidence: float = 0.7


@dataclass
class GlobalExclusions:
    """Exclusões globais padrão"""
    directories: List[str] = field(default_factory=lambda: [
        "__pycache__", ".git", ".svn", "node_modules", 
        ".idea", ".vscode", "venv", "env", ".env",
        "build", "dist", ".pytest_cache", "target",
        ".gradle", "cmake-build-debug", "cmake-build-release"
    ])
    file_patterns: List[str] = field(default_factory=lambda: [
        "*.pyc", "*.pyo", "*.log", "*.tmp", "*.bak",
        "*.swp", "*.swo", "*.DS_Store", "Thumbs.db"
    ])
    extensions: List[str] = field(default_factory=lambda: [
        ".min.js", ".min.css", ".map"
    ])


class ConfigManager:
    """
    Gerenciador central de configurações do CODVUNS.
    
    Implementa hierarquia: padrão → global → usuário → projeto → CLI
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Inicializa o gerenciador de configurações.
        
        Args:
            config_dir: Diretório de configurações (padrão: config/)
        """
        if config_dir is None:
            # Assume que está rodando da raiz do projeto
            self.config_dir = Path(__file__).parent
        else:
            self.config_dir = Path(config_dir)
        
        self.config_dir.mkdir(exist_ok=True)
        
        # Arquivos de configuração
        self.default_config_file = self.config_dir / "default.json"
        self.user_config_file = self.config_dir / "user.json"
        self.analysis_template_file = self.config_dir / "analysis_template.json"
        
        # Cache da configuração carregada
        self._config_cache: Optional[Dict[str, Any]] = None
        
        # Inicializar arquivos padrão se não existirem
        self._ensure_default_configs()
    
    def _ensure_default_configs(self):
        """Cria arquivos de configuração padrão se não existirem"""
        
        # Configuração padrão global
        if not self.default_config_file.exists():
            default_config = {
                "analysis": {
                    "max_file_size_mb": 10.0,
                    "max_depth": 10,
                    "timeout_seconds": 300,
                    "parallel_analysis": True,
                    "max_workers": 4
                },
                "reports": {
                    "default_format": "console",
                    "include_code_snippets": True,
                    "max_snippet_lines": 5,
                    "show_file_stats": True,
                    "color_output": True
                },
                "rules": {
                    "enabled_severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "disabled_rules": [],
                    "custom_rules_path": None,
                    "min_confidence": 0.7
                },
                "exclusions": {
                    "directories": [
                        "__pycache__", ".git", ".svn", "node_modules", 
                        ".idea", ".vscode", "venv", "env", ".env",
                        "build", "dist", ".pytest_cache", "target",
                        ".gradle", "cmake-build-debug", "cmake-build-release"
                    ],
                    "file_patterns": [
                        "*.pyc", "*.pyo", "*.log", "*.tmp", "*.bak",
                        "*.swp", "*.swo", "*.DS_Store", "Thumbs.db"
                    ],
                    "extensions": [".min.js", ".min.css", ".map"]
                },
                "cli": {
                    "verbose": False,
                    "quiet": False,
                    "progress_bar": True
                }
            }
            
            self._save_json_config(self.default_config_file, default_config)
        
        # Template de configuração de análise
        if not self.analysis_template_file.exists():
            analysis_template = {
                "project_name": "exemplo",
                "target_languages": ["python"],
                "excluded_paths": [],
                "custom_rules": [],
                "analysis_overrides": {},
                "report_preferences": {}
            }
            
            self._save_json_config(self.analysis_template_file, analysis_template)
    
    def load_config(self, project_path: Optional[str] = None, cli_args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Carrega configuração completa seguindo a hierarquia.
        
        Args:
            project_path: Caminho do projeto para buscar config local
            cli_args: Argumentos da CLI para sobrepor configurações
            
        Returns:
            Configuração final mesclada
        """
        config = {}
        
        # 1. Configuração padrão (base)
        if self.default_config_file.exists():
            config = self._load_json_config(self.default_config_file)
        
        # 2. Configuração do usuário (sobrepõe padrão)
        if self.user_config_file.exists():
            user_config = self._load_json_config(self.user_config_file)
            config = self._deep_merge(config, user_config)
        
        # 3. Configuração do projeto (se fornecida)
        if project_path:
            project_config_file = Path(project_path) / "config" / "project.json"
            if project_config_file.exists():
                project_config = self._load_json_config(project_config_file)
                config = self._deep_merge(config, project_config)
        
        # 4. Argumentos CLI (maior prioridade)
        if cli_args:
            config = self._merge_cli_args(config, cli_args)
        
        self._config_cache = config
        return config
    
    def get(self, key: str, default: Any = None, project_path: Optional[str] = None) -> Any:
        """
        Obtém valor de configuração usando notação de ponto.
        
        Args:
            key: Chave da configuração (ex: 'analysis.max_depth')
            default: Valor padrão se não encontrado
            project_path: Caminho do projeto para contexto
            
        Returns:
            Valor da configuração
        """
        if self._config_cache is None:
            self._config_cache = self.load_config(project_path)
        
        # Navega pela estrutura usando notação de ponto
        value = self._config_cache
        for part in key.split('.'):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        
        return value
    
    def set_user_preference(self, key: str, value: Any) -> None:
        """
        Define uma preferência do usuário e salva no arquivo.
        
        Args:
            key: Chave da configuração (notação de ponto)
            value: Valor a ser definido
        """
        # Carrega configuração atual do usuário
        user_config = {}
        if self.user_config_file.exists():
            user_config = self._load_json_config(self.user_config_file)
        
        # Define o valor usando notação de ponto
        self._set_nested_value(user_config, key, value)
        
        # Salva de volta
        self._save_json_config(self.user_config_file, user_config)
        
        # Limpa cache para forçar reload
        self._config_cache = None
    
    def create_project_config(self, project_path: str, **overrides) -> str:
        """
        Cria arquivo de configuração para um projeto específico.
        
        Args:
            project_path: Caminho do projeto
            **overrides: Configurações específicas do projeto
            
        Returns:
            Caminho do arquivo de configuração criado
        """
        project_config_dir = Path(project_path) / "config"
        project_config_dir.mkdir(exist_ok=True)
        
        project_config_file = project_config_dir / "project.json"
        
        # Carrega template base
        template = self._load_json_config(self.analysis_template_file)
        
        # Aplica overrides
        template.update(overrides)
        
        # Salva configuração do projeto
        self._save_json_config(project_config_file, template)
        
        return str(project_config_file)
    
    def _load_json_config(self, file_path: Path) -> Dict[str, Any]:
        """Carrega configuração de arquivo JSON"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"⚠️ Erro ao carregar {file_path}: {e}")
            return {}
    
    def _save_json_config(self, file_path: Path, config: Dict[str, Any]) -> None:
        """Salva configuração em arquivo JSON"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️ Erro ao salvar {file_path}: {e}")
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Mescla dicionários recursivamente"""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _merge_cli_args(self, config: Dict[str, Any], cli_args: Dict[str, Any]) -> Dict[str, Any]:
        """Mescla argumentos CLI na configuração"""
        result = config.copy()
        
        # Mapeamento de argumentos CLI para chaves de configuração
        cli_mapping = {
            'format': 'reports.default_format',
            'verbose': 'cli.verbose',
            'quiet': 'cli.quiet',
            'timeout': 'analysis.timeout_seconds',
            'max_depth': 'analysis.max_depth',
            'no_color': 'reports.color_output',  # Invertido
        }
        
        for cli_key, config_key in cli_mapping.items():
            if cli_key in cli_args and cli_args[cli_key] is not None:
                value = cli_args[cli_key]
                
                # Tratamentos especiais
                if cli_key == 'no_color':
                    value = not value  # Inverte a lógica
                
                self._set_nested_value(result, config_key, value)
        
        return result
    
    def _set_nested_value(self, config: Dict[str, Any], key: str, value: Any) -> None:
        """Define valor usando notação de ponto"""
        keys = key.split('.')
        current = config
        
        # Navega até o penúltimo nível
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        # Define o valor final
        current[keys[-1]] = value
    
    def reset_user_config(self) -> None:
        """Remove configurações do usuário, voltando ao padrão"""
        if self.user_config_file.exists():
            self.user_config_file.unlink()
        self._config_cache = None
    
    def get_config_summary(self, project_path: Optional[str] = None) -> Dict[str, Any]:
        """Retorna resumo das configurações ativas"""
        config = self.load_config(project_path)
        
        return {
            'analysis': config.get('analysis', {}),
            'rules': {
                'enabled_severities': config.get('rules', {}).get('enabled_severities', []),
                'disabled_rules_count': len(config.get('rules', {}).get('disabled_rules', [])),
                'min_confidence': config.get('rules', {}).get('min_confidence', 0.7)
            },
            'reports': {
                'default_format': config.get('reports', {}).get('default_format', 'console'),
                'color_output': config.get('reports', {}).get('color_output', True)
            },
            'exclusions_count': len(config.get('exclusions', {}).get('directories', []))
        }


# Factory function para uso fácil
def get_config_manager(config_dir: Optional[str] = None) -> ConfigManager:
    """Cria ou retorna instância do ConfigManager"""
    return ConfigManager(config_dir)