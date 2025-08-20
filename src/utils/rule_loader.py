"""
Utilitário para carregar e gerenciar regras de vulnerabilidades
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import os

# Importa yaml apenas se disponível
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from ..models.rule import Rule, RuleEngine, create_engine_with_default_rules


class RuleLoader:
    """Carregador de regras de vulnerabilidades"""
    
    def __init__(self, base_path: Optional[Union[str, Path]] = None):
        if base_path is None:
            # Localiza automaticamente a pasta rules
            current_dir = Path(__file__).parent
            self.base_path = current_dir.parent / "rules"
        else:
            self.base_path = Path(base_path)
    
    def load_builtin_rules(self) -> List[Rule]:
        """Carrega regras padrão do arquivo JSON"""
        print("📦 Carregando regras padrão do JSON...")
        
        # Localiza arquivo de regras padrão
        default_rules_file = self.base_path / "vulnerability_rules.json"
        
        if not default_rules_file.exists():
            print(f"⚠️  Arquivo de regras padrão não encontrado: {default_rules_file}")
            return []
        
        rules = self.load_json_rules(str(default_rules_file))
        print(f"✅ {len(rules)} regras padrão carregadas do JSON")
        return rules
    
    def load_json_rules(self, file_path: str) -> List[Rule]:
        """Carrega regras de um arquivo JSON"""
        rules = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Suporta tanto lista de regras quanto regra única
            if isinstance(data, list):
                rule_dicts = data
            else:
                rule_dicts = [data]
            
            for rule_dict in rule_dicts:
                try:
                    rule = Rule.from_dict(rule_dict)
                    rules.append(rule)
                except Exception as e:
                    print(f"⚠️  Erro ao carregar regra: {e}")
            
            print(f"✅ {len(rules)} regras carregadas de {file_path}")
            
        except Exception as e:
            print(f"❌ Erro ao carregar arquivo {file_path}: {e}")
        
        return rules
    
    def load_yaml_rules(self, file_path: str) -> List[Rule]:
        """Carrega regras de um arquivo YAML"""
        rules = []
        
        if not YAML_AVAILABLE:
            print("⚠️  PyYAML não está instalado. Use 'pip install pyyaml' para suporte YAML")
            return rules
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            # Suporta tanto lista de regras quanto regra única
            if isinstance(data, list):
                rule_dicts = data
            else:
                rule_dicts = [data]
            
            for rule_dict in rule_dicts:
                try:
                    rule = Rule.from_dict(rule_dict)
                    rules.append(rule)
                except Exception as e:
                    print(f"⚠️  Erro ao carregar regra: {e}")
            
            print(f"✅ {len(rules)} regras carregadas de {file_path}")
            
        except Exception as e:
            print(f"❌ Erro ao carregar arquivo {file_path}: {e}")
        
        return rules
    
    def load_rules_from_directory(self, directory_path: Optional[Union[str, Path]] = None) -> List[Rule]:
        """Carrega todas as regras de um diretório"""
        if directory_path is None:
            target_path = self.base_path
        else:
            target_path = Path(directory_path)
        
        if not target_path.exists():
            print(f"⚠️  Diretório {target_path} não existe")
            return []
        
        print(f"📁 Carregando regras de {target_path}")
        
        all_rules = []
        
        # Carrega arquivos JSON
        for json_file in target_path.glob("*.json"):
            rules = self.load_json_rules(str(json_file))
            all_rules.extend(rules)
        
        # Carrega arquivos YAML (apenas se PyYAML estiver disponível)
        if YAML_AVAILABLE:
            for yaml_file in target_path.glob("*.yaml"):
                rules = self.load_yaml_rules(str(yaml_file))
                all_rules.extend(rules)
            
            for yml_file in target_path.glob("*.yml"):
                rules = self.load_yaml_rules(str(yml_file))
                all_rules.extend(rules)
        
        print(f"📋 Total de regras carregadas do diretório: {len(all_rules)}")
        return all_rules
    
    def create_engine_with_all_rules(self) -> RuleEngine:
        """Cria engine com todas as regras (built-in + arquivos)"""
        print("🔧 Criando engine de regras...")
        
        engine = RuleEngine()
        
        # Carrega regras built-in
        builtin_rules = self.load_builtin_rules()
        for rule in builtin_rules:
            engine.add_rule(rule)
        
        # Carrega regras de arquivos
        file_rules = self.load_rules_from_directory()
        for rule in file_rules:
            engine.add_rule(rule)
        
        print(f"🚀 Engine criado com {len(engine.rules)} regras")
        return engine
    
    def save_rules_to_directory(self, rules: List[Rule], 
                               directory_path: Optional[Union[str, Path]] = None,
                               format_type: str = "json") -> bool:
        """Salva regras em um diretório"""
        if directory_path is None:
            target_path = self.base_path
        else:
            target_path = Path(directory_path)
        
        # Cria diretório se não existir
        try:
            target_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"❌ Erro ao criar diretório {target_path}: {e}")
            return False
        
        try:
            if format_type.lower() == "json":
                file_path = target_path / "exported_rules.json"
                rules_data = [rule.to_dict() for rule in rules]
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(rules_data, f, indent=2, ensure_ascii=False)
                
                print(f"✅ {len(rules)} regras salvas em {file_path}")
                
            elif format_type.lower() == "yaml":
                if not YAML_AVAILABLE:
                    print("❌ PyYAML não está instalado. Use 'pip install pyyaml' para salvar em YAML")
                    return False
                
                file_path = target_path / "exported_rules.yaml"
                rules_data = [rule.to_dict() for rule in rules]
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(rules_data, f, default_flow_style=False, 
                             allow_unicode=True, indent=2)
                
                print(f"✅ {len(rules)} regras salvas em {file_path}")
            
            else:
                print(f"❌ Formato não suportado: {format_type}")
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Erro ao salvar regras: {e}")
            return False
    
    def validate_rules(self, rules: List[Rule]) -> Dict[str, Any]:
        """Valida conjunto de regras"""
        validation_result = {
            'total_rules': len(rules),
            'valid_rules': 0,
            'invalid_rules': 0,
            'errors': [],
            'warnings': [],
            'duplicate_ids': []
        }
        
        seen_ids = set()
        
        for rule in rules:
            try:
                # Verifica ID duplicado
                if rule.id in seen_ids:
                    validation_result['duplicate_ids'].append(rule.id)
                    validation_result['errors'].append(f"ID duplicado: {rule.id}")
                else:
                    seen_ids.add(rule.id)
                
                # Verifica se tem patterns ou custom_analyzer
                if not rule.patterns:
                    validation_result['errors'].append(
                        f"Regra {rule.id} não tem patterns"
                    )
                
                # Warnings para regras sem metadados importantes
                if not rule.metadata.cwe_id:
                    validation_result['warnings'].append(
                        f"Regra {rule.id} não tem CWE ID"
                    )
                
                validation_result['valid_rules'] += 1
                
            except Exception as e:
                validation_result['invalid_rules'] += 1
                validation_result['errors'].append(f"Erro na regra {rule.id}: {e}")
        
        return validation_result
    
    def list_available_rules(self) -> Dict[str, Any]:
        """Lista regras disponíveis organizadas por categoria"""
        all_rules = []
        
        # Regras built-in
        all_rules.extend(self.load_builtin_rules())
        
        # Regras de arquivos
        # all_rules.extend(self.load_rules_from_directory())
        
        # Organiza por categoria
        by_category = {}
        by_severity = {}
        by_language = {}
        
        for rule in all_rules:
            # Por categoria
            cat = rule.category.value
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(rule)
            
            # Por severidade
            sev = rule.severity.value
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(rule)
            
            # Por linguagem
            for lang in rule.target_languages:
                if lang not in by_language:
                    by_language[lang] = []
                by_language[lang].append(rule)
        
        return {
            'total_rules': len(all_rules),
            'by_category': {cat: len(rules) for cat, rules in by_category.items()},
            'by_severity': {sev: len(rules) for sev, rules in by_severity.items()},
            'by_language': {lang: len(rules) for lang, rules in by_language.items()},
            'rules': all_rules
        }


def get_default_rule_engine() -> RuleEngine:
    """Função utilitária para obter engine padrão com todas as regras"""
    loader = RuleLoader()
    return loader.create_engine_with_all_rules()


def save_default_rules_to_files():
    """Salva regras padrão em arquivos para referência"""
    print("💾 As regras padrão já estão em src/rules/vulnerability_rules.json")
    print("✅ Para criar novas regras, edite esse arquivo ou crie novos .json na pasta rules/")
    
    loader = RuleLoader()
    
    # Valida regras existentes
    rules = loader.load_builtin_rules()
    if rules:
        validation = loader.validate_rules(rules)
        print(f"📋 Validação: {validation['valid_rules']} válidas, {validation['invalid_rules']} inválidas")
        if validation['errors']:
            print("❌ Erros encontrados:")
            for error in validation['errors']:
                print(f"  - {error}")
    
    return len(rules)


if __name__ == "__main__":
    # Demonstração
    print("🧪 Testando RuleLoader")
    
    loader = RuleLoader()
    
    # Lista regras disponíveis
    print("\n📋 Listando regras disponíveis:")
    info = loader.list_available_rules()
    print(f"Total: {info['total_rules']} regras")
    print(f"Por categoria: {info['by_category']}")
    print(f"Por severidade: {info['by_severity']}")
    print(f"Por linguagem: {info['by_language']}")
    
    # Cria engine
    print("\n🔧 Criando engine:")
    engine = loader.create_engine_with_all_rules()
    stats = engine.get_stats()
    print(f"Engine com {stats['total_rules']} regras ativas")
    
    # Salva regras padrão
    print("\n💾 Salvando regras padrão:")
    save_default_rules_to_files()