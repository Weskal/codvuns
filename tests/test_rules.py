# tests/test_rule_clean.py
"""
Teste simples para o modelo de dados rule.py
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.models.rule import Rule, RuleEngine, RuleType, VulnerabilityCategory
from src.models.finding import Severity

def test_rule_basic():
    """Teste básico de criação de regra"""
    print("🧪 Testando criação de regra...")
    
    rule = Rule(
        id="TEST_001",
        name="Teste SQL Injection",
        description="Detecta SQL injection básico",
        severity=Severity.HIGH,
        category=VulnerabilityCategory.INJECTION,
        rule_type=RuleType.REGEX,
        patterns=["SELECT.*FROM.*WHERE"]
    )
    
    print(f"✅ Regra criada: {rule.id} - {rule.name}")
    print(f"   Severidade: {rule.severity}")
    print(f"   Categoria: {rule.category}")
    print()

def test_rule_engine():
    """Teste básico do engine"""
    print("🧪 Testando rule engine...")
    
    engine = RuleEngine()
    
    # Adiciona regra
    rule = Rule(
        id="ENGINE_001",
        name="Regra de Teste",
        description="Teste",
        severity=Severity.MEDIUM,
        category=VulnerabilityCategory.XSS,
        rule_type=RuleType.REGEX,
        patterns=["<script>"]
    )
    
    engine.add_rule(rule)
    
    print(f"✅ Engine tem {len(engine.rules)} regra(s)")
    
    # Busca regra
    found = engine.get_rule("ENGINE_001")
    print(f"✅ Regra encontrada: {found.name if found else 'Não encontrada'}")
    print()

def test_json_serialization():
    """Teste de serialização JSON"""
    print("🧪 Testando JSON...")
    
    rule = Rule(
        id="JSON_001",
        name="Teste JSON",
        description="Teste de serialização",
        severity=Severity.LOW,
        category=VulnerabilityCategory.HARDCODED_SECRETS,
        rule_type=RuleType.REGEX,
        patterns=["password.*="]
    )
    
    # Para JSON
    json_str = rule.to_json()
    print(f"✅ JSON gerado: {len(json_str)} caracteres")
    
    # De JSON
    rule_dict = rule.to_dict()
    restored = Rule.from_dict(rule_dict)
    print(f"✅ Regra restaurada: {restored.id}")
    print()

if __name__ == "__main__":
    print("🧪 Teste simples do rule.py\n")
    
    try:
        test_rule_basic()
        test_rule_engine()
        test_json_serialization()
        
        print("✅ Todos os testes passaram!")
        
    except Exception as e:
        print(f"❌ Erro: {e}")
        import traceback
        traceback.print_exc()