from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Set, Any
from datetime import datetime
from enum import Enum
import os
import json


class ProjectLanguage(Enum):
    """Linguagens de programação suportadas"""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CPP = "cpp"
    C = "c"
    PHP = "php"
    RUBY = "ruby"
    GO = "go"
    RUST = "rust"
    CSHARP = "csharp"
    STYLESHEET = "stylesheet" # Não é uma linguagem de programação, mas serve bem estar aqui como arquivo de estilo
    UNKNOWN = "unknown"

    @classmethod
    def detect_from_extension(cls, file_path: str) -> 'ProjectLanguage':
        """Detecta a linguagem baseada na extensão do arquivo"""
        extension_map = {
            '.py': cls.PYTHON,
            '.js': cls.JAVASCRIPT,
            '.ts': cls.TYPESCRIPT,
            '.jsx': cls.JAVASCRIPT,
            '.tsx': cls.TYPESCRIPT,
            '.java': cls.JAVA,
            '.cpp': cls.CPP,
            '.cc': cls.CPP,
            '.cxx': cls.CPP,
            '.c': cls.C,
            '.h': cls.C,
            '.hpp': cls.CPP,
            '.php': cls.PHP,
            '.rb': cls.RUBY,
            '.go': cls.GO,
            '.rs': cls.RUST,
            '.cs': cls.CSHARP,
            '.css': cls.STYLESHEET
        }
        
        ext = Path(file_path).suffix.lower()
        return extension_map.get(ext, cls.UNKNOWN)


@dataclass
class ProjectFile:
    """Representa um arquivo dentro do projeto"""
    path: str
    language: ProjectLanguage
    size_bytes: int
    last_modified: datetime
    
    @classmethod
    def from_path(cls, file_path: Path, project_root: Path) -> 'ProjectFile':
        """Cria ProjectFile a partir de um caminho"""
        stat = file_path.stat()
        relative_path = file_path.relative_to(project_root)
        
        return cls(
            path=str(relative_path),
            language=ProjectLanguage.detect_from_extension(str(file_path)),
            size_bytes=stat.st_size,
            last_modified=datetime.fromtimestamp(stat.st_mtime)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return {
            'path': self.path,
            'language': self.language.value,
            'size_bytes': self.size_bytes,
            'last_modified': self.last_modified.isoformat()
        }


@dataclass
class ProjectStats:
    """Estatísticas do projeto"""
    total_files: int = 0
    total_lines: int = 0
    total_size_bytes: int = 0
    languages: Dict[ProjectLanguage, int] = field(default_factory=dict)
    
    def add_file(self, file: ProjectFile, line_count: int = 0):
        """Adiciona um arquivo às estatísticas"""
        self.total_files += 1
        self.total_lines += line_count
        self.total_size_bytes += file.size_bytes
        
        if file.language in self.languages:
            self.languages[file.language] += 1
        else:
            self.languages[file.language] = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário"""
        return {
            'total_files': self.total_files,
            'total_lines': self.total_lines,
            'total_size_bytes': self.total_size_bytes,
            'languages': {lang.value: count for lang, count in self.languages.items()}
        }


@dataclass
class Project:
    """
    Representa um projeto de código para análise de vulnerabilidades
    """
    name: str
    root_path: str
    files: List[ProjectFile] = field(default_factory=list)
    
    # Configurações de análise
    target_languages: Set[ProjectLanguage] = field(default_factory=set)
    excluded_paths: List[str] = field(default_factory=list)
    included_extensions: Set[str] = field(default_factory=set)
    
    # Metadados
    created_at: Optional[datetime] = None
    last_scanned: Optional[datetime] = None
    description: Optional[str] = None
    
    # Estatísticas
    stats: ProjectStats = field(default_factory=ProjectStats)
    
    def __post_init__(self):
        """Inicialização após criação do objeto"""
        if self.created_at is None:
            self.created_at = datetime.now()
        
        # Converte string para Path se necessário
        self.root_path = str(Path(self.root_path).resolve())
        
        # Define extensões padrão se não especificadas
        if not self.included_extensions:
            self.included_extensions = {
                '.py', '.js', '.ts', '.jsx', '.tsx', '.java', 
                '.cpp', '.c', '.h', '.hpp', '.php', '.rb', 
                '.go', '.rs', '.cs'
            }
    
    @property
    def root_path_obj(self) -> Path:
        """Retorna o caminho raiz como objeto Path"""
        return Path(self.root_path)
    
    @property
    def size_mb(self) -> float:
        """Tamanho total do projeto em MB"""
        return self.stats.total_size_bytes / (1024 * 1024)
    
    @property
    def primary_language(self) -> ProjectLanguage:
        """Linguagem principal do projeto (mais comum)"""
        if not self.stats.languages:
            return ProjectLanguage.UNKNOWN
        
        return max(self.stats.languages.items(), key=lambda x: x[1])[0]
    
    def discover_files(self, max_depth: int = 10) -> int:
        """
        Descobre arquivos no projeto
        Retorna o número de arquivos encontrados
        """
        if not self.root_path_obj.exists():
            raise FileNotFoundError(f"Caminho do projeto não existe: {self.root_path}")
        
        self.files.clear()
        self.stats = ProjectStats()
        
        discovered_count = 0
        
        try:
            for file_path in self._walk_files(self.root_path_obj, max_depth):
                if self._should_include_file(file_path):
                    project_file = ProjectFile.from_path(file_path, self.root_path_obj)
                    self.files.append(project_file)
                    
                    # Conta linhas (simplificado - só conta quebras de linha)
                    line_count = self._count_lines(file_path)
                    self.stats.add_file(project_file, line_count)
                    
                    discovered_count += 1
        
        except Exception as e:
            print(f"Erro ao descobrir arquivos: {e}")
        
        return discovered_count
    
    def _walk_files(self, root: Path, max_depth: int, current_depth: int = 0):
        """Caminha pelos arquivos do projeto respeitando a profundidade máxima"""
        if current_depth > max_depth:
            return
        
        try:
            for item in root.iterdir():
                if item.is_file():
                    yield item
                elif item.is_dir() and not self._is_excluded_path(item):
                    yield from self._walk_files(item, max_depth, current_depth + 1)
        except PermissionError:
            # Ignora diretórios sem permissão
            pass
    
    def _should_include_file(self, file_path: Path) -> bool:
        """Verifica se um arquivo deve ser incluído na análise"""
        # Verifica extensão
        if file_path.suffix.lower() not in self.included_extensions:
            return False
        
        # Verifica caminhos excluídos
        if self._is_excluded_path(file_path):
            return False
        
        # Verifica linguagens alvo (se especificadas)
        if self.target_languages:
            file_language = ProjectLanguage.detect_from_extension(str(file_path))
            if file_language not in self.target_languages:
                return False
        
        return True
    
    def _is_excluded_path(self, path: Path) -> bool:
        """Verifica se um caminho está na lista de exclusões"""
        path_str = str(path.relative_to(self.root_path_obj))
        
        # Exclusões padrão
        default_exclusions = {
            '__pycache__', '.git', '.svn', 'node_modules', 
            '.idea', '.vscode', 'venv', 'env', '.env',
            'build', 'dist', '.pytest_cache'
        }
        
        # Verifica se alguma parte do caminho está nas exclusões
        path_parts = set(path.parts)
        if path_parts.intersection(default_exclusions):
            return True
        
        # Verifica exclusões customizadas
        for excluded in self.excluded_paths:
            if excluded in path_str or path_str.startswith(excluded):
                return True
        
        return False
    
    def _count_lines(self, file_path: Path) -> int:
        """Conta linhas de um arquivo (implementação simples)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
    
    def get_files_by_language(self, language: ProjectLanguage) -> List[ProjectFile]:
        """Retorna arquivos filtrados por linguagem"""
        return [f for f in self.files if f.language == language]
    
    def add_excluded_path(self, path: str):
        """Adiciona um caminho à lista de exclusões"""
        if path not in self.excluded_paths:
            self.excluded_paths.append(path)
    
    def set_target_languages(self, languages: List[str]):
        """Define as linguagens alvo para análise"""
        self.target_languages = {
            ProjectLanguage(lang.lower()) for lang in languages
            if lang.lower() in [l.value for l in ProjectLanguage]
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte projeto para dicionário"""
        return {
            'name': self.name,
            'root_path': self.root_path,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_scanned': self.last_scanned.isoformat() if self.last_scanned else None,
            'target_languages': [lang.value for lang in self.target_languages],
            'excluded_paths': self.excluded_paths,
            'included_extensions': list(self.included_extensions),
            'stats': self.stats.to_dict(),
            'files': [f.to_dict() for f in self.files]
        }
    
    def to_json(self) -> str:
        """Serializa projeto para JSON"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Project':
        """Cria projeto a partir de dicionário"""
        # Converte datas
        if data.get('created_at'):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if data.get('last_scanned'):
            data['last_scanned'] = datetime.fromisoformat(data['last_scanned'])
        
        # Converte linguagens
        if 'target_languages' in data:
            data['target_languages'] = {
                ProjectLanguage(lang) for lang in data['target_languages']
            }
        
        # Converte extensões para set
        if 'included_extensions' in data:
            data['included_extensions'] = set(data['included_extensions'])
        
        # Remove arquivos e stats do dict (serão recriados)
        data.pop('files', None)
        data.pop('stats', None)
        
        return cls(**data)
    
    def __str__(self) -> str:
        """Representação legível do projeto"""
        return (f"Project '{self.name}' ({self.stats.total_files} files, "
                f"{self.primary_language.value}, {self.size_mb:.1f}MB)")
    
    def __repr__(self) -> str:
        """Representação técnica do projeto"""
        return (f"Project(name='{self.name}', root_path='{self.root_path}', "
                f"files_count={len(self.files)})")


def create_project(name: str, root_path: str, **kwargs) -> Project:
    """Factory function para criar projeto"""
    return Project(name=name, root_path=root_path, **kwargs)


def load_project_from_json(json_path: str) -> Project:
    """Carrega projeto de um arquivo JSON"""
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return Project.from_dict(data)