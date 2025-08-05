from typing import List, Dict
from ..models.finding import Finding, Severity


class SecurityScoreCalculator:
    """
    Calculadora de score de segurança para análise de vulnerabilidades.
    
    Implementa o sistema de pontuação onde 100 = código sem problemas
    e cada vulnerabilidade desconta pontos baseado na severidade.
    """
    
    # Mapeamento de severidade para penalidade
    SEVERITY_PENALTIES = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 7,
        Severity.MEDIUM: 5,
        Severity.LOW: 3,
        Severity.INFO: 1
    }
    
    @classmethod
    def calculate_security_score(cls, findings: List[Finding]) -> float:
        """
        Calcula o score de segurança baseado nos findings.
        
        Args:
            findings: Lista de vulnerabilidades encontradas
            
        Returns:
            Score de 0-100 onde 100 = sem problemas
        """
        if not findings:
            return 100.0
            
        total_penalty = sum(
            cls.SEVERITY_PENALTIES[finding.severity] 
            for finding in findings
        )
        
        return max(0.0, 100.0 - total_penalty)
    
    @classmethod
    def calculate_severity_counts(cls, findings: List[Finding]) -> Dict[Severity, int]:
        """
        Conta findings por severidade.
        
        Args:
            findings: Lista de vulnerabilidades encontradas
            
        Returns:
            Dicionário com contadores por severidade
        """
        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0
        }
        
        for finding in findings:
            counts[finding.severity] += 1
            
        return counts
    
    @classmethod
    def get_score_classification(cls, score: float) -> str:
        """
        Classifica o score em categorias legíveis.
        
        Args:
            score: Score de segurança (0-100)
            
        Returns:
            Classificação textual do score
        """
        if score == 100: 
            return "Código limpo - sem vulnerabilidades"
        if score >= 90:
            return "Excelente - código minimamente vulnerável"
        elif score >= 75:
            return "Bom - código precisa de revisão de segurança"
        elif score < 50 and score >= 25:
            return "Ruim - é necessário um refatoramento do código e medidas de segurança à serem tomadas"
        else:
            return "Crítico!!!"