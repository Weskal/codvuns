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
        
    
    def analyze(self, target_path):
        # 1. Criar ProjectDetector e detectar projeto
        # 2. Criar RuleLoader e carregar regras  
        # 3. Escolher analyzer apropriado
        # 4. Executar análise
        # 5. Gerar relatório
        
        pass
    
    