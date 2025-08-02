from dataclasses import dataclass #facilita a criação de classes com atributos sem escrever muito (como __init__, __repr__, etc)
from enum import Enum # Define conjuntos fixos de valores
from typing import Optional, Dict, Any
from datetime import datetime
import json

class Severity(Enum):
    
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __str__(self):
        return self.value
    
    @property
    def color(self):
        
        colors = {
            'CRITICAL': 'bold red',
            'HIGH':'red',
            'MEDIUM':'yellow',
            'LOW':'blue',
            'INFO':'green'
        }
        return colors.get(self.value, 'white')
        
    @property
    def score(self):
        
        scores = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 5,
            'LOW': 3,
            'INFO': 1
        }
        
@dataclass
class Finding:
    """
    Esta classe representa uma vulnerabilidade encontrada durante a análise.
    """
    
    # __init__.py substituido pela lib dataclasses
    file_path: str
    line_number: int
    rule_id: str
    severity: Severity
    message: str
    
    # Campos opcionais
    column: Optional[int] = None
    code_snippet: Optional[str] = None
    category: Optional[str] = None
    cwe_id: Optional[str] = None  # Common Weakness Enumeration
    confidence: Optional[float] = None  # 0.0 a 1.0
    
    # Metadados
    found_at: Optional[datetime] = None
    
    def __post__init(self):
        
        # Define a data caso não tenha sido informada
        if self.found_at is None:
            self.found_at = datetime.now()
            
        # Converter string para Severity se necessário
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.upper())
    
    def __str__(self) -> str:
        """Representação legível para humanos
           Exemplo: arquivo.py:52 (nome do arquivo:numero da linha)
        """
        
        location = f"{self.file_path}:{self.line_number}"
        if self.column:
            location += f":{self.column}"
            
        return f"[{self.severity.value}] {self.message} ({location})"
    
    def __repr__(self) -> str:
        """Representação técnica para debug
           Exemplo: Finding(file_path='app.py', line_number=42, rule_id='SQL_INJECTION', severity=Severity.HIGH)
        """
        return (f"Finding(file_path='{self.file_path}', "
                f"line_number={self.line_number}, "
                f"rule_id='{self.rule_id}', "
                f"severity={self.severity})")
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário (JSON/Relatórios)"""
        return {
            'file_path':self.file_path,
            'line_number': self.line_number,
            'column': self.column,
            'rule_id': self.rule_id,
            'severity': self.severity.value,
            'message': self.message,
            'category': self.category,
            'cwe_id': self.cwe_id,
            'confidence': self.confidence,
            'code_snippet': self.code_snippet,
            'found_at': self.found_at.isoformat() if self.found_at else None
        }
   
    @classmethod
    def from_dict(cls,data:Dict[str,Any])->'Finding':
        """Cria o finding a partir de um dicionário"""
        if data.get('found_at'):
            data['found_at'] = datetime.fromisoformat(data['found_at'])
        return cls(**data)
    
    def to_json(self)->str:
        """Serializa o contexto para sair em formato JSON"""
        
        return json.dumps(self.to_dict(),indent=2,ensure_ascii=False)
    
    @property
    def location(self)-> str:
        """Recebe a localização formatada"""    
        if self.column:
            return f"{self.file_path}:{self.line_number}:{self.column}"
        return f"{self.file_path}:{self.line_number}"
    
    @property 
    def is_high_priority(self)-> bool:
        """Propriedade que verifica se a 'anomalia' é de gravidade alta ou crítica"""
        return self.severity in [Severity.CRITICAL, Severity.HIGH]
    
    
def create_finding(file_path: str, line_number: int, rule_id: str, 
                severity: str, message: str, **kwargs) -> Finding:
    """Factory function para criar Finding de forma mais simples"""
    return Finding(
    file_path=file_path,
    line_number=line_number,
    rule_id=rule_id,
    severity=Severity(severity.upper()),
    message=message,
    **kwargs
    )

def filter_findings_by_severity(findings: list, min_severity: Severity) -> list:
    """Filtra findings por severidade mínima"""
    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, 
                     Severity.HIGH, Severity.CRITICAL]
    min_index = severity_order.index(min_severity)
    
    return [f for f in findings 
            if severity_order.index(f.severity) >= min_index]


