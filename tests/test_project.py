# tests/test_project.py
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.models.project import Project, ProjectLanguage, create_project

def test_project_creation():
    """Testa a criação básica de um projeto"""
    print("=== Teste: Criação de Projeto ===")
    
    project = create_project(
        name="CODVUNS Test",
        root_path=".",  # Diretório atual
        description="Projeto de teste do scanner CODVUNS"
    )
    
    print(f"Projeto criado: {project}")
    print(f"Caminho raiz: {project.root_path}")
    print(f"Linguagem primária: {project.primary_language}")
    print(f"Extensões incluídas: {project.included_extensions}")
    print()

def test_file_discovery():
    """Testa a descoberta de arquivos"""
    print("=== Teste: Descoberta de Arquivos ===")
    
    project = create_project(
        name="Auto Discovery Test",
        root_path="."
    )
    
    # Adiciona algumas exclusões específicas
    project.add_excluded_path("tests")
    project.add_excluded_path("reports")
    
    # Descobre arquivos
    file_count = project.discover_files()
    
    print(f"Arquivos descobertos: {file_count}")
    print(f"Estatísticas do projeto:")
    print(f"  - Total de arquivos: {project.stats.total_files}")
    print(f"  - Total de linhas: {project.stats.total_lines}")
    print(f"  - Tamanho total: {project.size_mb:.2f} MB")
    print(f"  - Linguagem principal: {project.primary_language.value}")
    
    print(f"\nDistribuição por linguagem:")
    for lang, count in project.stats.languages.items():
        print(f"  - {lang.value}: {count} arquivo(s)")
    
    print(f"\nPrimeiros 5 arquivos encontrados:")
    for i, file in enumerate(project.files[:5]):
        print(f"  {i+1}. {file.path} ({file.language.value}) - {file.size_bytes} bytes")
    print()

def test_language_filtering():
    """Testa filtragem por linguagem"""
    print("=== Teste: Filtragem por Linguagem ===")
    
    project = create_project(
        name="Language Filter Test",
        root_path="."
    )
    
    # Define apenas Python como linguagem alvo
    project.set_target_languages(['python'])
    
    file_count = project.discover_files()
    
    print(f"Arquivos Python encontrados: {file_count}")
    python_files = project.get_files_by_language(ProjectLanguage.PYTHON)
    
    print(f"Arquivos Python específicos:")
    for file in python_files:
        print(f"  - {file.path}")
    print()

def test_json_serialization():
    """Testa serialização JSON"""
    print("=== Teste: Serialização JSON ===")
    
    project = create_project(
        name="JSON Test",
        root_path=".",
        description="Teste de serialização"
    )
    
    project.discover_files()
    
    # Converte para JSON
    json_data = project.to_json()
    print("Projeto serializado para JSON:")
    print(json_data[:500] + "..." if len(json_data) > 500 else json_data)
    print()

def test_language_detection():
    """Testa detecção de linguagens"""
    print("=== Teste: Detecção de Linguagens ===")
    
    test_files = [
        "app.py",
        "script.js", 
        "component.tsx",
        "Main.java",
        "program.cpp",
        "style.css",
        "readme.txt"
    ]
    
    for filename in test_files:
        lang = ProjectLanguage.detect_from_extension(filename)
        print(f"  {filename} -> {lang.value}")
    print()

if __name__ == "__main__":
    print("Executando testes do Project\n")
    
    try:
        test_project_creation()
        test_language_detection()
        test_file_discovery()
        test_language_filtering()
        test_json_serialization()
        
        print("✅ Todos os testes concluídos com sucesso!")
        
    except Exception as e:
        print(f"Erro durante os testes: {e}")
        import traceback
        traceback.print_exc()