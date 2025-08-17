from abc import ABC, abstractclassmethod
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging
from ..models.finding import Finding, Severity

class BaseAnalyzer(ABC):
    """
    Classe base abstrata para todos os analisadores (anlyzers) de código.
    
    Define a interface comum que todos os analyzers devem implementar, conferindo
    consistência na API e permitindo polimorfismo no Scanner
    """
    
    def __init__(self):
        """Inicializa o analyzer base"""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.name = self.__class__.__name__
        
    # Métodos abstratos:    
    
    @classmethod
    def analyze(cls, file_path: str, rules: List, config: Any) -> List[Finding]:
        """
        Método principal de análise: Deve ser implementado por cada um dos analzyers.
        
        Args:
            file_path: Caminho do arquivo a ser analisado
            rules: Lista de regras aplicáveis ao arquivo
            config: Configurações de análise
            
        Returns: 
            Lista de vulnerabilidades encontradas
            
        Raise:
            NotImplementedError: Se não implementado pela subclasse
        """
        raise NotImplementedError("Subclasses devem implementar o método analyze()")
    
    @classmethod
    def get_supported_languages(cls) -> List[str]:
        """
        Retorna uma lista com as linguagens suportadas pelo analyzer.
        
        Returns:
            Lista de strings com nomes das linguagens (ex: ["python","ruby"])
        """
        raise NotImplementedError("Subclasses devem implementar get_supported_languages()")
    
    
    @classmethod
    def get_supported_extensions(cls) -> List[str]:
        """
        Retorna uma lista de extensões de arquivos suportadas.
        
        Returns:
            Lista de extensões (ex: [".py",".cs"])
        """
        raise NotImplementedError("Subclasses devem implementar get_supported_extensions()")
    
    # Métodos utilitários:
    
    def can_analyze_file(self, file_path: str) -> bool:
        """
        Verifica se este analyzer pode analisar o arquivo dado.
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            True se pode analisar, False caso contrário
        """
        file_extension = Path(file_path).suffix.lower()
        return file_extension in self.get_supported_extensions()
    
    def filter_applicable_rules(self, rules: List, file_path: str) -> List:
        """
        Filtra regras aplicáveis a este analyzer e arquivo específico.
        
        Args:
            rules: Lista com as regras
            file_path: Caminho do arquivo em análise
            
        Returns:
            Lista de regras que se aplicam ao arquivo
        """
        
        applicable_rules = []
        supported_languages = self.get_supported_languages()
        
        for rule in rules:
            if not rule.target_languages:
                # Regra sem linguagem específica = aplica a todos
                applicable_rules.append(rule)
                
            else:
                for rule_lang in rule.targe_languages:
                    if rule_lang in supported_languages:
                        applicable_rules.append(rule)
                        break
                    
        return applicable_rules
    
    def create_finding(self, file_path: str, line_number: int, rule_id: str, severity: Severity, message: str, **kwargs) -> Finding:
        """
        Factory method para criar objetos Finding de forma consistente e eficaz.
        
        Args:
            file_path: Caminho do arquivo
            line_number: Número da linha no arquivo
            rule_id: ID da regra que detectou
            severity: Severidade da vulnerabilidade (LOW, MEDIUM...)
            message: Mensagem descritiva
            **kwargs: Campos opcionais
            
        Returns:
            Objeto Finding configurado
        """
        
        return Finding(
            file_path = file_path,
            line_number = line_number,
            rule_id = rule_id,
            severity = severity,
            message = message,
            **kwargs,
        )
                        
    def read_files(self, file_path: str) -> Optional[str]:
        """
        Lê o arquivo de forma segura com tratamento de erros.
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Conteúdo do arquivo ou None se der erro
        """
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: 
                return f.read()
        except Exception as e:
            self.logger.warning(f"Erro ao ler o arquivo {e}")
            return None
        
    def count_lines(self, content: str) -> int:
        """
        Conta o número de linhas no conteúdo.
        
        Args:
            content: Conteúdo do arquivo
            
        Returns:
            Número de linhas
        """
        
        if not content:
            return 0
        return len(content.splitlines())
    
    def get_line_content(self, content: str, line_number: int) -> str:
        """
        Obtém conteúdo de uma linha específica.
        
        Args:
            content: Conteúdo completo do arquivo
            line_number: Número da linha
            
        Returns:
            Conteúdo da linha ou string vazia se não encontrada
        """
        
        try:
            lines = content.splitlines()
            if 1 <= line_number <= len(lines):
                return lines[line_number - 1]
            return ""
        except Exception:
            return ""
        
    def get_code_snippet(self, content: str, line_number: int, context_lines: int = 2) -> str:
        """
        Obtém snippet de código ao redor de uma linha.
        
        Args:
            content: Conteúdo completo do arquivo
            line_number: Linha central do snippet
            context_lines: Número de linhas de contexto antes e depois
            
        Returns:
            Snippet de código
        """
        
        try:
            lines = content.splitlines()
            start = max(0, line_number - context_lines -1)
            end = min(len(lines), line_number + context_lines)
            
            snippet_lines = []
            
            for i in range(start, end):
                line_num = i+1
                marker = ">>> " if line_num == line_number else "   "
                snippet_lines.append(f"{marker}{line_num:3d}")
            
            return "\n".join(snippet_lines)
        
        except Exception:
            return f"Linha {line_number: {self.get_line_content(content, line_number)}}"
        
    def validate_config(self, config: Any) -> Dict[str, Any]:
        """
        Valida configurações específicas para este analyzer.
        
        Args:
            config: Objeto de configuração
        
        Returns:
            Dicionário com configurações validadas e warnings
        """
        
        return {
            "valid": True,
            "warnings": [],
            "config": config
        }
        
    def get_analyzer_info(self) -> Dict[str, Any]:
        """
        Retorna informações sobre este analyzer.
        
        Returns:
            Dicionário com metadados do analyzer
        """
        return {
            "name": self.name,
            "supported_languages": self.get_supported_languages(),
            "supported_extensions": self.get_supported_extensions(),
            "version": "1.0.0",
            "description": self.__doc__ or f"Analyzer para {', '.join(self.get_supported_languages())}"
        }
    
    def __str__(self) -> str:
        """Representação string do analyzer"""
        languages = ", ".join(self.get_supported_languages())
        return f"{self.name}({languages})"
    
    def __repr__(self) -> str:
        """Representação técnica do analyzer"""
        return f"{self.__class__.__name__}(languages={self.get_supported_languages()})"
    
class AnalyzerRegistry:
    """
    Registry para gerenciar analyzers disponíveis.
    
    Permite registrar, descobrir e escolher analyzers apropriados para cada
    projeto baseado em linguagem ou extensão de arquivo.
    """
    
    def __init__(self):
        self._analyzers: Dict[str, BaseAnalyzer] = {}
        self._language_map: Dict[str, str] = {}
        self._extension_map: Dict[str, str] = {}
        
    
    def register(self, analyzer: BaseAnalyzer) -> None:
        """
        Registra um analyzer no registry.
        
        Args:
            analyzer: Instância do analyzer a ser registrado
        """
        name = analyzer.__class__.__name__
        self._analyzers[name] = analyzer
        
        for language in analyzer.get_supported_languages():
            self._language_map[language] = name
            
        for extension in analyzer.get_supported_extensions():
            self._extension_map[extension] = name
            
    def get_analyzer_for_language(self, language: str) -> Optional[BaseAnalyzer]:
        """
        Obtém analyzer apropriado para uma linguagem.
        
        Args:
            language: Nome da linguagem (ex: python)
            
        Returns: 
            Analyzer apropriado ou None se não encontrado
        """
        analyzer_name = self._language_map.get(language.lower())
        return self._analyzers.get(analyzer_name) if analyzer_name else None
    
    def get_analyzer_for_file(self, file_path: str) -> Optional[BaseAnalyzer]:
        """
        Obtém anapyzer apropriado para uma arquivo
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Analyzer apropriado ou None se não encontrado
        """
        
        extension = Path(file_path).suffix.lower()
        analyzer_name = self._extension_map.get(extension)
        return self._analyzers.get(analyzer_name) if analyzer_name else None
    
    def list_analyzers(self) -> List[Dict[str, Any]]:
        """
        Lista todos os analyzers registrados.
        
        Returns:
            Lista com todos os analyzers
        """
        
        return [analyzer.get_analyzer_info() for analyzer in self._analyzers.values()]
    
    def get_supported_languages(self) -> List[str]:
        """
        Retorna as linguagens suportadas por todos os analyzers presentes
        
        Returns:
            Lista de linguagens suportadas por todos os analyzers
        """
        return list(self._language_map.keys())
    
# Instância global do registry

analyzer_registry = AnalyzerRegistry()