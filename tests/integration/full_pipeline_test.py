#!/usr/bin/env python3
"""
Teste de Pipeline Completo do CODVUNS
=====================================

Este teste simula um cenário real de análise de vulnerabilidades em um projeto Python.
Cria um projeto vulnerável temporário e executa todo o pipeline do scanner.
"""

import sys
import os
import tempfile
import shutil
from pathlib import Path

# Adiciona o diretório raiz do projeto ao Python path
# De tests/integration/ para a raiz codvuns/
project_root = os.path.join(os.path.dirname(__file__), '..', '..')
sys.path.insert(0, project_root)

from src.core.scanner import Scanner
from src.core.project_detector import ProjectDetector
from src.utils.rule_loader import RuleLoader
from config.settings import ConfigManager
from src.models.finding import Severity


class VulnerableProjectSimulator:
    """Simula um projeto Python com vulnerabilidades conhecidas"""
    
    def __init__(self, temp_dir: str):
        self.temp_dir = Path(temp_dir)
        self.project_name = "excel_data_uploader"
        
    def create_vulnerable_project(self):
        """Cria um projeto Python vulnerável com múltiplas falhas de segurança"""
        
        # Cria estrutura do projeto
        project_root = self.temp_dir / self.project_name
        project_root.mkdir(parents=True, exist_ok=True)
        
        # 1. Arquivo principal com vulnerabilidades críticas
        main_py = project_root / "main.py"
        main_py.write_text('''#!/usr/bin/env python3
"""
Excel Data Uploader - VERSÃO VULNERÁVEL PARA TESTE
==================================================
Este script lê dados de um arquivo Excel e faz upload para banco de dados.
ATENÇÃO: Este código contém vulnerabilidades intencionais para teste!
"""

import os
import sqlite3
import pandas as pd
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# VULNERABILIDADE 1: Hardcoded secrets
DB_PASSWORD = "super_secret_123"
API_KEY = "sk-1234567890abcdefghijklmnop"
SECRET_TOKEN = "admin_token_2024"

# VULNERABILIDADE 2: Configuração insegura
app.config['DEBUG'] = True  # Debug mode em produção!

def connect_database():
    """Conecta ao banco de dados usando credenciais hardcoded"""
    connection_string = f"postgresql://admin:{DB_PASSWORD}@localhost/production"
    return connection_string

def process_excel_file(file_path, user_query=None):
    """Processa arquivo Excel e executa queries no banco"""
    
    # Lê o arquivo Excel
    try:
        df = pd.read_excel(file_path)
        print(f"Arquivo carregado: {len(df)} registros")
    except Exception as e:
        print(f"Erro ao carregar Excel: {e}")
        return None
    
    # VULNERABILIDADE 3: SQL Injection
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    for _, row in df.iterrows():
        # Query vulnerável - concatenação direta
        query = f"INSERT INTO users (name, email) VALUES ('{row['name']}', '{row['email']}')"
        cursor.execute(query)
    
    # Query personalizada do usuário (ainda mais perigosa!)
    if user_query:
        dangerous_query = "SELECT * FROM users WHERE " + user_query
        cursor.execute(dangerous_query)
    
    conn.commit()
    conn.close()

def execute_system_command(command):
    """Executa comandos do sistema - MUITO PERIGOSO!"""
    
    # VULNERABILIDADE 4: Command Injection
    full_command = "echo 'Processing: " + command + "'"
    os.system(full_command)
    
    # Também vulnerável com subprocess
    subprocess.run(f"ls -la {command}", shell=True)

def dynamic_code_execution(user_code):
    """Executa código Python fornecido pelo usuário"""
    
    # VULNERABILIDADE 5: Code Injection
    print("Executando código personalizado...")
    eval(user_code)  # Extremamente perigoso!
    
    # Ainda pior:
    exec(user_code)

@app.route('/upload', methods=['POST'])
def upload_endpoint():
    """Endpoint para upload de arquivos Excel"""
    
    # VULNERABILIDADE 6: XSS via template
    filename = request.form.get('filename', 'unknown')
    
    # Template vulnerável
    template = f"<h1>Arquivo {filename} processado!</h1>"
    return render_template_string(template)

@app.route('/admin')
def admin_panel():
    """Painel administrativo"""
    
    # VULNERABILIDADE 7: Autenticação fraca
    password = request.args.get('password')
    if password == "admin123":  # Senha fraca hardcoded
        return "Acesso liberado ao painel admin"
    
    return "Acesso negado"

if __name__ == "__main__":
    print("Iniciando Excel Data Uploader...")
    
    # Exemplo de uso vulnerável
    excel_file = input("Digite o caminho do arquivo Excel: ")
    user_filter = input("Digite filtro SQL (opcional): ")
    system_cmd = input("Digite comando do sistema: ")
    python_code = input("Digite código Python para executar: ")
    
    # Executa funções vulneráveis
    process_excel_file(excel_file, user_filter)
    execute_system_command(system_cmd)
    dynamic_code_execution(python_code)
    
    # Inicia servidor web vulnerável
    app.run(host='0.0.0.0', port=5000, debug=True)
''')

        # 2. Arquivo de configuração com mais problemas
        config_py = project_root / "config.py"
        config_py.write_text('''"""
Configurações do sistema - VULNERÁVEL
"""

import hashlib

# VULNERABILIDADE: Mais hardcoded secrets
DATABASE_URL = "mysql://root:password123@localhost/prod"
ENCRYPTION_KEY = "my_secret_key_2024"
JWT_SECRET = "jwt_secret_token_super_secret"

# VULNERABILIDADE: Algoritmo criptográfico fraco
def hash_password(password):
    """Hash de senha usando MD5 - INSEGURO!"""
    return hashlib.md5(password.encode()).hexdigest()

def legacy_crypto():
    """Função que usa SHA1 - obsoleto"""
    return hashlib.sha1(b"data").hexdigest()

# VULNERABILIDADE: Configurações perigosas
ALLOWED_EXTENSIONS = ['exe', 'bat', 'sh']  # Permite executáveis!
UPLOAD_FOLDER = '/tmp'
MAX_FILE_SIZE = 999999999  # Sem limite real
''')

        # 3. Arquivo utils com mais vulnerabilidades
        utils_py = project_root / "utils.py"
        utils_py.write_text('''"""
Utilitários do sistema
"""

import os
import pickle

def load_user_data(data_string):
    """Carrega dados do usuário - VULNERÁVEL A DESERIALIZATION"""
    
    # VULNERABILIDADE: Insecure Deserialization
    user_data = pickle.loads(data_string)
    return user_data

def backup_files(source_dir):
    """Faz backup de arquivos"""
    
    # VULNERABILIDADE: Path traversal + Command injection
    backup_cmd = f"tar -czf backup.tar.gz {source_dir}/../*"
    os.system(backup_cmd)

def log_user_activity(user_input):
    """Registra atividade do usuário"""
    
    # VULNERABILIDADE: Log injection
    log_message = f"User activity: {user_input}"
    
    # Escreve no log sem sanitização
    with open('/var/log/app.log', 'a') as f:
        f.write(log_message + "\\n")
''')

        # 4. Requirements.txt
        requirements = project_root / "requirements.txt"
        requirements.write_text('''flask==2.0.1
pandas==1.3.0
openpyxl==3.0.7
sqlite3
''')

        # 5. Arquivo README
        readme = project_root / "README.md"
        readme.write_text('''# Excel Data Uploader

Sistema para upload e processamento de dados Excel.

## ATENÇÃO
Este é um projeto de TESTE com vulnerabilidades intencionais!
NÃO use em produção!

## Funcionalidades
- Upload de arquivos Excel
- Processamento de dados
- Interface web
- Comandos administrativos

## Como usar
1. Execute `python main.py`
2. Forneça o arquivo Excel
3. Configure filtros opcionais
''')

        print(f"✅ Projeto vulnerável criado em: {project_root}")
        return str(project_root)


def run_complete_pipeline_test():
    """Executa teste completo do pipeline CODVUNS"""
    
    print("=" * 60)
    print("🧪 TESTE DE PIPELINE COMPLETO - CODVUNS")
    print("=" * 60)
    
    temp_dir = None
    
    try:
        # 1. Cria projeto temporário vulnerável
        print("\n📁 Criando projeto vulnerável temporário...")
        temp_dir = tempfile.mkdtemp(prefix="codvuns_test_")
        simulator = VulnerableProjectSimulator(temp_dir)
        project_path = simulator.create_vulnerable_project()
        
        # 2. Inicializa componentes do CODVUNS
        print("\n🔧 Inicializando componentes do CODVUNS...")
        
        # Cria configuração
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # Cria scanner
        scanner = Scanner(config_manager)
        
        print("✅ Scanner inicializado")
        
        # 3. Executa análise completa
        print(f"\n🔍 Executando análise de vulnerabilidades em: {project_path}")
        print("-" * 50)
        
        # Executa o pipeline completo
        result = scanner.analyze(project_path)
        
        # 4. Exibe resultados
        print("\n📊 RESULTADOS DA ANÁLISE")
        print("=" * 40)
        
        report = result.report
        stats = result.stats
        
        print(f"Projeto analisado: {report.target_path}")
        print(f"Arquivos analisados: {stats.files_analyzed}")
        print(f"Arquivos ignorados: {stats.files_skipped}")
        print(f"Regras aplicadas: {stats.rules_applied}")
        print(f"Regras que encontraram problemas: {stats.rules_triggered}")
        print(f"Total de linhas escaneadas: {stats.total_lines_scanned}")
        print(f"Tempo de execução: {stats.execution_time:.2f}s")
        
        print(f"\n🏆 SCORE DE SEGURANÇA: {report.summary.security_score:.1f}/100")
        
        print(f"\n📋 RESUMO DE VULNERABILIDADES:")
        print(f"  🔴 Críticas: {report.summary.critical_count}")
        print(f"  🟠 Altas: {report.summary.high_count}")
        print(f"  🟡 Médias: {report.summary.medium_count}")
        print(f"  🔵 Baixas: {report.summary.low_count}")
        print(f"  ℹ️  Informativas: {report.summary.info_count}")
        print(f"  📊 Total: {report.summary.total_findings}")
        
        # 5. Lista vulnerabilidades encontradas
        if report.findings:
            print(f"\n🚨 VULNERABILIDADES DETECTADAS:")
            print("-" * 50)
            
            # Agrupa por severidade
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                severity_findings = report.get_findings_by_severity(severity)
                if severity_findings:
                    print(f"\n{severity.value} ({len(severity_findings)} encontradas):")
                    for finding in severity_findings[:5]:  # Mostra até 5 por severidade
                        print(f"  📍 {finding.file_path}:{finding.line_number}")
                        print(f"     Regra: {finding.rule_id}")
                        print(f"     Mensagem: {finding.message}")
                        if finding.code_snippet:
                            print(f"     Código: {finding.code_snippet[:80]}...")
                        print()
                    
                    if len(severity_findings) > 5:
                        print(f"     ... e mais {len(severity_findings) - 5} vulnerabilidades")
        
        # 6. Mostra erros se houver
        if result.errors:
            print(f"\n⚠️  ERROS DURANTE ANÁLISE:")
            for error in result.errors[:10]:  # Mostra até 10 erros
                print(f"  - {error}")
        
        # 7. Validação do teste
        print(f"\n✅ VALIDAÇÃO DO TESTE:")
        print("-" * 30)
        
        test_passed = True
        
        # Verifica se encontrou vulnerabilidades esperadas
        if report.summary.total_findings < 5:
            print("❌ Poucas vulnerabilidades encontradas (esperado: >= 5)")
            test_passed = False
        else:
            print(f"✅ Vulnerabilidades encontradas: {report.summary.total_findings}")
        
        # Verifica se encontrou vulnerabilidades críticas/altas
        high_priority = report.summary.critical_count + report.summary.high_count
        if high_priority < 3:
            print("❌ Poucas vulnerabilidades de alta prioridade (esperado: >= 3)")
            test_passed = False
        else:
            print(f"✅ Vulnerabilidades de alta prioridade: {high_priority}")
        
        # Verifica se análise foi rápida
        if stats.execution_time > 30:
            print(f"⚠️  Análise demorou muito: {stats.execution_time:.2f}s")
        else:
            print(f"✅ Tempo de análise aceitável: {stats.execution_time:.2f}s")
        
        # Verifica tipos específicos de vulnerabilidades
        expected_patterns = ['SQL_INJECTION', 'HARDCODED', 'COMMAND_INJECTION', 'DANGEROUS_FUNCTION']
        found_patterns = [f.rule_id for f in report.findings]
        
        for pattern in expected_patterns:
            if any(pattern in rule_id for rule_id in found_patterns):
                print(f"✅ Detectou {pattern}")
            else:
                print(f"⚠️  Não detectou {pattern}")
        
        # 8. Resultado final
        print(f"\n🎯 RESULTADO FINAL DO TESTE:")
        if test_passed:
            print("🎉 TESTE PASSOU! O pipeline CODVUNS está funcionando corretamente.")
        else:
            print("❌ TESTE FALHOU! Verifique os problemas identificados acima.")
        
        # 9. Relatório JSON (opcional)
        try:
            import json
            
            # Primeiro vamos testar se o to_dict() tem problemas
            report_dict = report.to_dict()
            
            # Função para converter Path objects recursivamente
            def clean_paths(obj):
                if isinstance(obj, dict):
                    return {k: clean_paths(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [clean_paths(item) for item in obj]
                elif hasattr(obj, '__fspath__'):  # É um Path object
                    return str(obj)
                else:
                    return obj
            
            # Limpa paths antes de serializar
            clean_dict = clean_paths(report_dict)
            
            json_report_path = os.path.join(temp_dir, "codvuns_report.json")
            with open(json_report_path, 'w', encoding='utf-8') as f:
                json.dump(clean_dict, f, indent=2, ensure_ascii=False)
            print(f"\n📄 Relatório JSON salvo em: {json_report_path}")
        except Exception as e:
            print(f"⚠️  Erro ao salvar relatório JSON: {e}")
            # Vamos ver qual campo está causando problema
            try:
                print("🔍 Investigando qual campo tem Path object...")
                test_dict = report.to_dict()
                for key, value in test_dict.items():
                    try:
                        json.dumps(value)
                        print(f"  ✅ {key}: OK")
                    except Exception as field_error:
                        print(f"  ❌ {key}: {field_error}")
            except Exception as debug_error:
                print(f"  Debug falhou: {debug_error}")
        
        return test_passed, result
        
    except Exception as e:
        print(f"\n❌ ERRO DURANTE O TESTE: {e}")
        import traceback
        traceback.print_exc()
        return False, None
        
    finally:
        # Limpa arquivos temporários
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
                print(f"\n🧹 Arquivos temporários removidos: {temp_dir}")
            except Exception as e:
                print(f"⚠️  Erro ao remover arquivos temporários: {e}")


if __name__ == "__main__":
    print("Iniciando teste de pipeline completo do CODVUNS...")
    
    # Executa o teste
    success, analysis_result = run_complete_pipeline_test()
    
    # Código de saída
    sys.exit(0 if success else 1)