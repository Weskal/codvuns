from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

from .finding import Finding, Severity
from ..utils.scoring import SecurityScoreCalculator


class ReportFormat(Enum):
    """Formatos de saída suportados para relatórios"""
    CONSOLE = "console"
    JSON = "json" 
    HTML = "html"
    CSV = "csv"


@dataclass
class ReportSummary:
    """Resumo executivo do relatório de análise"""
    
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    security_score: float = 100.0  # 0-100, onde 100 é o melhor
    
    def __post_init__(self):
        """Valida consistência dos dados"""
        expected_total = (self.critical_count + self.high_count + 
                         self.medium_count + self.low_count + self.info_count)
        if self.total_findings != expected_total:
            self.total_findings = expected_total


@dataclass 
class Report:
    """
    Representa um relatório completo de análise de vulnerabilidades.
    
    Esta é a estrutura base que será expandida nas próximas semanas
    com funcionalidades de geração, formatação e exportação.
    """
    
    # Dados principais
    target_path: str
    findings: List[Finding] = field(default_factory=list)
    
    # Metadados da análise
    scan_started_at: datetime = field(default_factory=datetime.now)
    scan_duration: Optional[float] = None  # em segundos
    analyzer_version: str = "1.0.0"
    
    # Resumo (será calculado automaticamente)
    summary: ReportSummary = field(init=False)
    
    def __post_init__(self):
        """Calcula automaticamente o resumo após inicialização"""
        self.summary = self._calculate_summary()
    
    def _calculate_summary(self) -> ReportSummary:
        """Calcula resumo baseado nos findings atuais"""
        
        # Usa o SecurityScoreCalculator para contar severidades
        severity_counts = SecurityScoreCalculator.calculate_severity_counts(self.findings)
        
        # Calcula score de segurança usando o calculator
        security_score = SecurityScoreCalculator.calculate_security_score(self.findings)
        
        return ReportSummary(
            total_findings=len(self.findings),
            critical_count=severity_counts[Severity.CRITICAL],
            high_count=severity_counts[Severity.HIGH],
            medium_count=severity_counts[Severity.MEDIUM], 
            low_count=severity_counts[Severity.LOW],
            info_count=severity_counts[Severity.INFO],
            security_score=security_score
        )
    
    def add_finding(self, finding: Finding) -> None:
        """Adiciona um finding e recalcula o resumo"""
        self.findings.append(finding)
        self.summary = self._calculate_summary()
    
    def add_findings(self, findings: List[Finding]) -> None:
        """Adiciona múltiplos findings e recalcula o resumo"""
        self.findings.extend(findings)
        self.summary = self._calculate_summary()
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Retorna findings filtrados por severidade"""
        return [f for f in self.findings if f.severity == severity]
    
    def get_high_priority_findings(self) -> List[Finding]:
        """Retorna apenas findings de alta prioridade (CRITICAL e HIGH)"""
        return [f for f in self.findings if f.is_high_priority]
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário (preparação para JSON/relatórios)"""
        return {
            'target_path': self.target_path,
            'scan_started_at': self.scan_started_at.isoformat(),
            'scan_duration': self.scan_duration,
            'analyzer_version': self.analyzer_version,
            'summary': {
                'total_findings': self.summary.total_findings,
                'critical_count': self.summary.critical_count,
                'high_count': self.summary.high_count,
                'medium_count': self.summary.medium_count,
                'low_count': self.summary.low_count,
                'info_count': self.summary.info_count,
                'security_score': self.summary.security_score
            },
            'findings': [finding.to_dict() for finding in self.findings]
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Report':
        """Cria Report a partir de dicionário"""
        # Reconstrói findings
        findings = [Finding.from_dict(f_data) for f_data in data.get('findings', [])]
        
        # Reconstrói datas
        scan_started_at = datetime.fromisoformat(data['scan_started_at'])
        
        return cls(
            target_path=data['target_path'],
            findings=findings,
            scan_started_at=scan_started_at,
            scan_duration=data.get('scan_duration'),
            analyzer_version=data.get('analyzer_version', '1.0.0')
        )
    
    def to_json(self) -> str:
        """Serializa para JSON"""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
    
    @property
    def is_clean(self) -> bool:
        """Verifica se não há vulnerabilidades encontradas"""
        return len(self.findings) == 0
    
    @property 
    def has_critical_issues(self) -> bool:
        """Verifica se há issues críticos"""
        return self.summary.critical_count > 0
    
    def __str__(self) -> str:
        """Representação legível do relatório"""
        return (f"Report({self.target_path}): "
                f"{self.summary.total_findings} findings, "
                f"score: {self.summary.security_score:.1f}/100")

# Caso não houver vulnerabilidades
def create_empty_report(target_path: str) -> Report:
    """Factory function para criar relatório vazio"""
    return Report(target_path=target_path)

# Caso houver vulnerabilidades
def create_report_from_findings(target_path: str, findings: List[Finding]) -> Report:
    """Factory function para criar relatório com findings"""
    return Report(target_path=target_path, findings=findings)