from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
import time
import logging

# Imports dos componentes do sistema
from ..models.finding import Finding
from ..models.project import Project
from ..models.report import Report
from ..utils.scoring import SecurityScoreCalculator
from ..utils.rule_loader import RuleLoader
from .project_detector import ProjectDetector

@dataclass
class AnalysisStats:
    """Estatísticas da análise executada"""
    files_analyzed: int = 0
    files_skipped: int = 0
    rules_applied: int = 0
    rules_triggered: int = 0
    total_lines_scanned: int = 0
    execution_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte estatísticas para dicionário"""
        return {
            'files_analyzed': self.files_analyzed,
            'files_skipped': self.files_skipped,
            'rules_applied': self.rules_applied,
            'rules_triggered': self.rules_triggered,
            'total_lines_scanned': self.total_lines_scanned,
            'execution_time': self.execution_time
        }


@dataclass
class AnalysisResult:
    """Resultado completo da análise"""
    report: Report
    stats: AnalysisStats
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte resultado para dicionário"""
        return {
            'report': self.report.to_dict(),
            'stats': self.stats.to_dict(),
            'errors': self.errors
        }

class Scanner:
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.project_detector = None
        self.rule_loader = None
       
    def validate_config(self) -> List[str]:
        """Valida as configurações e corrige valores inválidos"""
        
        warnings = []
        
        # Configs críticas
        
        validations = {
            "analysis.max_file_size_mb": (0.1, 100, 10.0, "MB"),
            "analysis.max_depth": (1, 20, 10, "níveis"),
            "analysis.timeout_seconds": (10, 3600, 300, "segundos"),
            "analysis.max_workers": (1, 16, 4, "workers"),
            "rules.min_confidence": (0.0, 1.0, 0.7, "confiança")
        }
        
        # Valida as configs numéricas
        
        for config_key, (min_val, max_val, default, unit) in validations.items():
            value = self.config.get(config_key, default)
            
            if value < min_val:
                self.config.set_user_preference(config_key, min_val)
                warnings.append(f"{config_key} muito abaixo do mínimo permitido, ajustado para {min_val} {unit}")
                
            elif value > max_val:
                self.config.set_user_preference(config_key, max_val)
                warnings.append(f"{config_key} ultrapassou o limite, limitado a {max_val} {unit}")
                
        # Validações extras (listas, caminhos, etc...)
        
        directories = self.config.get("exclusions.directories", [])
        if not isinstance(directories, list):
            self.config.set_user_preference("exclusions.directories", [])
            warnings.append("exclusions.directories inválido, usando lista vazia para análise")    
            
        return warnings
         
    def detect_project(self, target_path: str) -> Project:
        """Detecta e analisa o projeto alvo
        Args: 
                target_path
        Returns: 
                Objeto Project
        Raises:
                FileNotFoundError: Se o caminho não existir
                ValueError: Se não for um projeto válido
        """
        
        self.logger.info(f"Detectando projeto em: {target_path}...")
        
        # Cria o detector
        
        if self.project_detector is None:
            self.project_detector = ProjectDetector()
            
        # Valida o caminho do projeto
        
        if not self.project_detector.is_valid_project(target_path):
            raise ValueError(f"Caminho não contém um projeto válido: {target_path}")
        
        project = self.project_detector.detect_project(target_path)
        
        self.logger.info(f"Projeto detectado: {project.name} ({project.primary_language.value})")
        self.logger.info(f"Arquivos encontrados: {len(project.files)}")
        
        return project
    
    def load_rules(self, project: Project) -> List:
        """
        Carrega regras que se aplicam ao projeto.
        
        Args:
            project: Projeto detectado para filtrar regras que deram "match"
        
        Returns:
            Lista de regras que se aplicam ao projeto
        """
        
        self.logger.info("Carregando regras de vulnerabilidade...")
        
        # Cria o rule loader para carregar as regras
        
        if self.rule_loader is None:
            self.rule_loader = RuleLoader()
        
        all_rules = self.rule_loader.load_builtin_rules()
        
        # Converte linguagens do projeto para strings ex: de ProjectLanguage.JAVA para só java
        project_languages = []
        for language in project.target_languages:
            project_languages.append(language.value)
        
        # Filtra regras aplicáveis ao projeto
        applicable_rules = []
        for rule in all_rules:
            
            # Caso a regra não especifique linguagens, aceita qualquer projeto
            if (not rule.target_languages or 
                any(lang in rule.target_languages for lang in [tl.value for tl in project.target_languages])):
                applicable_rules.append(rule)
        
        self.logger.info(f"Regras carregadas: {len(all_rules)} no total, {len(applicable_rules)} aplicáveis ao projeto")
        
        return applicable_rules
    
    def choose_analyzer(self, project: Project):
        """
        Escolhe o analisador baseado na linguagem principal do projeto
        
        Args:
            project: Projeto com linguagem detectada
            
        Returns: 
            Instância do analisador apropriado
            
        Raises:
            NotImplemetedError: Se linguagem não suportada ou não existir
        """
        
        from ..models.project import ProjectLanguage
        
        # Escolha do analisador baseada na linguagem principal
        if project.primary_language == ProjectLanguage.PYTHON:
            # Import dinâmico para evitar dependência circular
        #     try:
        #         from ..analyzers.python_analyzer import PythonAnalyzer
        #         return PythonAnalyzer()
        #     except ImportError:
        #         self.logger.warning("PythonAnalyzer não encontrado, usando analyzer básico")
        #         return self._get_basic_analyzer()
        
        # else:
        #     self.logger.warning(f"Linguagem {project.primary_language.value} não suportada")
        #     return self._get_basic_analyzer()
            pass
        
        ## Remover comentários quando o analisador python for criado
        
    def execute_analysis(self, project: Project, rules: List, analyzer, stats: AnalysisStats) -> tuple[List[Finding], List[str]]:
        """
        Executa a análise principal nos arquivos do projeto.
        
        Args:
            project: Projeto a ser analisado
            rules: Regras aplicáveis
            analyzer: Analisador escolhido
            stats: Estatísticas para atualizar
            
        Returns:
            Lista de vulnerabilidades encontradas
        """
        self.logger.info("Iniciando análise de vulnerabilidades...")
        
        findings = []
        errors = []
        
        # Configurações para análise
        max_file_size = self.config.get("analysis.max_file_size_mb", 10.0) * 1024 * 1024  # bytes
        timeout = self.config.get("analysis.timeout_seconds", 300)
        
        # Análise incremental arquivo por arquivo
        for project_file in project.files:
            try:
                file_path = Path(project.root_path) / project_file.path
                
                # Verifica tamanho do arquivo
                if project_file.size_bytes > max_file_size:
                    stats.files_skipped += 1
                    errors.append(f"{project_file.path}: Arquivo muito grande ({project_file.size_bytes} bytes)")
                    continue
                
                # Análise do arquivo (implementação será expandida nas Semanas 3-4)
                file_findings = analyzer.analyze(file_path, rules, self.config)
                findings.extend(file_findings)
                
                # Atualiza estatísticas
                stats.files_analyzed += 1
                stats.total_lines_scanned += self._count_lines(file_path)
                
                # Log de progresso
                if stats.files_analyzed % 10 == 0:
                    self.logger.info(f"Analisados {stats.files_analyzed} arquivos...")
                
            except Exception as e:
                stats.files_skipped += 1
                error_msg = f"{project_file.path}: {str(e)}"
                errors.append(error_msg)
                self.logger.warning(f"Erro ao analisar arquivo: {error_msg}")
        
        # Conta regras que foram aplicadas vs que encontraram algo
        stats.rules_applied = len(rules)
        stats.rules_triggered = len(set(finding.rule_id for finding in findings))
        
        self.logger.info(f"Análise concluída: {len(findings)} vulnerabilidades encontradas")
        
        return findings, errors
    
    def _count_lines(self, file_path: Path) -> int:
        """
        Conta linhas de um arquivo.
        
        Args:
            file_path: Caminho do arquivo
            
        Returns:
            Número de linhas do arquivo
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
        
    def generate_report(self, project: Project, findings: List[Finding]) -> Report:
        """
        Gera relatório final da análise.
        
        Args:
            project: Projeto analisado
            findings: Vulnerabilidades encontradas
            
        Retruns:
            Relatório completo com score calculado
        """
        
        self.logger.info("Gerando relatório final...")
        
        report = Report(
            target_path=project.root_path,
            findings=findings
        )
        
        # Score é calculado automaticamente pelo report via SecurityScoreCalculator

        self.logger.info(f"Relatório gerado: Score {report.summary.security_score:.1f}/100")
        
        return report
    
    def show_warnings(self, warnings: List[str]) -> None:
        """
        Exibe warnings de configuração para o usuário.
        
        Args:
            warnings: Lista de mensagens de warning
        """
        
        if warnings:
            print("\n Avisos de Configuração:")
            for warning in warnings:
                print(f" - {warning}")
            print()
    
    def analyze(self, target_path: str) -> AnalysisResult:
        """
        Método principal - executa análise completa do projeto.
        
        Args:
            target_path: Caminho para o projeto a ser analisado
            
        Returns:
            Resultado completo análise com relatório, estatísticas e erros
            
        Raises:
            FileNotFoundError: Se o projeto não encontrado
            ValueError: Se projeto inválido
        """
        
        start_time = time.time()
        
        # Inicializa estatísticas
        stats = AnalysisStats()
        errors = []
        
        try:
            # 1. Validar configurações
            self.logger.info("--- Iniciando Análise de Vulnerabilidades ---")
            warnings = self.validate_config()
            self.show_warnings(warnings)
            
            # 2. Detectar projeto
            project = self.detect_project(target_path)
            
            # 3. Carregar as regras
            rules = self.load_rules(project)
            
            # 4. Escolher analyzer adequado
            analyzer = self.choose_analyzer(project)
            
            # 5. Executar análise
            findings, analysis_errors = self.execute_analysis(project, rules, analyzer, stats)
            errors.extend(analysis_errors)
            
            # 6. Gerar relatório
            report = self.generate_report(project, findings)
            
            self.logger.info(f"=== Análise concluída em {stats.execution_time:.2f}s ===")
            
            return AnalysisResult(
                report=report,
                stats=stats,
                errors=errors
            )
        except Exception as e:
            stats.execution_time = time.time() - start_time
            self.logger.error(f"Erro durante análise: {str(e)}")
            
            # Mesmo com erro, retorna o resultado
            empty_report = Report(target_path=target_path, findings=[])
            return AnalysisResult(
                report=empty_report,
                stats=stats,
                errors=[f"Erro crítico: {str(e)}"]
            )
            
# Função para criar o scanner
def create_scanner(config) -> Scanner:
    """
    Factory function para criar a instância do Scanner.
    
    Args:
        config: ConfigManager ou dicionário (dict) com as configurações
    
    Returns:
        Instância configurada do Scanner
    """
    return Scanner(config)
    
    