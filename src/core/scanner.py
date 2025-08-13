from pathlib import Path
from typing import Optional, List, Dict, Set, Any
from ...config.settings import ConfigManager
import os

class Scanner:
    def __init__(self, config):
        self.config = config
       
    def validate_config(self):
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
         
    
    def analyze(self, target_path):
        # 1. Criar ProjectDetector e detectar projeto
        # 2. Criar RuleLoader e carregar regras  
        # 3. Escolher analyzer apropriado
        # 4. Executar análise
        # 5. Gerar relatório
        
        pass
    
    