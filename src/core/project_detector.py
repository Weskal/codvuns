from pathlib import Path
from typing import Optional, List, Dict, Set, Any
import os

from ..models.project import Project, ProjectLanguage, create_project


class ProjectDetector:
    """
    Detector básico de projetos para análise de vulnerabilidades.
    
    Detecta tipo, estrutura e configurações de projetos de código
    para preparar a análise adequada.
    """
    
    # Arquivos que indicam tipos específicos de projeto
    PROJECT_INDICATORS = {
        ProjectLanguage.PYTHON: [
            'requirements.txt', 'setup.py', 'pyproject.toml', 
            'Pipfile', 'poetry.lock', 'conda.yml'
        ],
        ProjectLanguage.JAVASCRIPT: [
            'package.json', 'package-lock.json', 'yarn.lock',
            'webpack.config.js', 'gulpfile.js'
        ],
        ProjectLanguage.TYPESCRIPT: [
            'tsconfig.json', 'tslint.json', 'angular.json'
        ],
        ProjectLanguage.JAVA: [
            'pom.xml', 'build.gradle', 'gradle.properties',
            'build.xml', 'ivy.xml'
        ],
        ProjectLanguage.CPP: [
            'CMakeLists.txt', 'Makefile', 'configure.ac',
            'meson.build', 'vcpkg.json'
        ],
        ProjectLanguage.C: [
            'Makefile', 'configure.ac', 'meson.build'
        ],
        ProjectLanguage.PHP: [
            'composer.json', 'composer.lock'
        ],
        ProjectLanguage.RUBY: [
            'Gemfile', 'Gemfile.lock', 'Rakefile'
        ],
        ProjectLanguage.GO: [
            'go.mod', 'go.sum', 'Gopkg.toml'
        ],
        ProjectLanguage.RUST: [
            'Cargo.toml', 'Cargo.lock'
        ],
        ProjectLanguage.CSHARP: [
            '*.csproj', '*.sln', 'packages.config'
        ]
    }
    
    def __init__(self):
        """Inicializa o detector"""
        pass
    
    def detect_project(self, path: str) -> Project:
        """
        Detecta e cria um objeto Project baseado no diretório fornecido.
        
        Args:
            path: Caminho para o diretório do projeto
            
        Returns:
            Objeto Project configurado com base na detecção
            
        Raises:
            FileNotFoundError: Se o caminho não existir
            NotADirectoryError: Se o caminho não for um diretório
        """
        project_path = Path(path).resolve()
        
        # Validações básicas
        if not project_path.exists():
            raise FileNotFoundError(f"Caminho não encontrado: {path}")
        
        if not project_path.is_dir():
            raise NotADirectoryError(f"Caminho não é um diretório: {path}")
        
        # Detecta informações do projeto
        project_name = self._detect_project_name(project_path)
        primary_language = self._detect_primary_language(project_path)
        target_languages = self._detect_target_languages(project_path)
        
        # Cria o projeto
        project = create_project(
            name=project_name,
            root_path=str(project_path),
            target_languages=target_languages
        )
        
        # Adiciona exclusões específicas baseadas no tipo de projeto
        self._configure_exclusions(project, primary_language)
        
        # Descobre arquivos automaticamente
        try:
            files_found = project.discover_files()
            print(f"✅ Detectado projeto '{project_name}' ({primary_language.value})")
            print(f"📁 {files_found} arquivos encontrados")
        except Exception as e:
            print(f"⚠️ Erro ao descobrir arquivos: {e}")
        
        return project
    
    def _detect_project_name(self, project_path: Path) -> str:
        """Detecta o nome do projeto"""
        # Tenta extrair de package.json
        package_json = project_path / 'package.json'
        if package_json.exists():
            try:
                import json
                with open(package_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'name' in data:
                        return data['name']
            except Exception:
                pass
        
        # Tenta extrair de setup.py
        setup_py = project_path / 'setup.py'
        if setup_py.exists():
            try:
                with open(setup_py, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Busca padrão name="projeto"
                    import re
                    match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
                    if match:
                        return match.group(1)
            except Exception:
                pass
        
        # Fallback: usa o nome do diretório
        return project_path.name
    
    def _detect_primary_language(self, project_path: Path) -> ProjectLanguage:
        """
        Detecta a linguagem principal do projeto baseada em indicadores.
        """
        # Conta pontos por linguagem baseado em indicadores encontrados
        language_scores = {}
        
        # Verifica arquivos indicadores
        for language, indicators in self.PROJECT_INDICATORS.items():
            score = 0
            for indicator in indicators:
                if '*' in indicator:
                    # Padrão glob (ex: *.csproj)
                    pattern = indicator.replace('*', '')
                    matching_files = list(project_path.glob(f"**/*{pattern}"))
                    score += len(matching_files) * 2
                else:
                    # Arquivo específico
                    if (project_path / indicator).exists():
                        score += 3
            
            if score > 0:
                language_scores[language] = score
        
        # Se não encontrou indicadores, analisa extensões de arquivo
        if not language_scores:
            language_scores = self._detect_by_file_extensions(project_path)
        
        # Retorna a linguagem com maior pontuação
        if language_scores:
            return max(language_scores.items(), key=lambda x: x[1])[0]
        
        return ProjectLanguage.UNKNOWN
    
    def _detect_target_languages(self, project_path: Path) -> Set[ProjectLanguage]:
        """
        Detecta todas as linguagens presentes no projeto.
        """
        found_languages = set()
        
        # Adiciona linguagens com indicadores
        for language, indicators in self.PROJECT_INDICATORS.items():
            for indicator in indicators:
                if '*' in indicator:
                    pattern = indicator.replace('*', '')
                    if list(project_path.glob(f"**/*{pattern}")):
                        found_languages.add(language)
                        break
                else:
                    if (project_path / indicator).exists():
                        found_languages.add(language)
                        break
        
        # Adiciona linguagens encontradas por extensão
        extension_languages = self._detect_by_file_extensions(project_path)
        found_languages.update(extension_languages.keys())
        
        # Remove UNKNOWN se outras linguagens foram encontradas
        if len(found_languages) > 1 and ProjectLanguage.UNKNOWN in found_languages:
            found_languages.remove(ProjectLanguage.UNKNOWN)
        
        return found_languages or {ProjectLanguage.UNKNOWN}
    
    def _detect_by_file_extensions(self, project_path: Path) -> Dict[ProjectLanguage, int]:
        """
        Detecta linguagens contando arquivos por extensão.
        """
        language_counts = {}
        
        # Lista algumas extensões comuns para amostragem rápida
        sample_extensions = ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.php', '.rb', '.go', '.rs', '.cs']
        
        for ext in sample_extensions:
            files = list(project_path.glob(f"**/*{ext}"))
            if files:
                language = ProjectLanguage.detect_from_extension(f"file{ext}")
                if language != ProjectLanguage.UNKNOWN:
                    language_counts[language] = len(files)
        
        return language_counts
    
    def _configure_exclusions(self, project: Project, primary_language: ProjectLanguage):
        """
        Configura exclusões específicas baseadas no tipo de projeto.
        """
        # Exclusões específicas por linguagem
        if primary_language == ProjectLanguage.PYTHON:
            project.add_excluded_path('__pycache__')
            project.add_excluded_path('.pytest_cache')
            project.add_excluded_path('venv')
            project.add_excluded_path('env')
        
        elif primary_language == ProjectLanguage.JAVASCRIPT:
            project.add_excluded_path('node_modules')
            project.add_excluded_path('dist')
            project.add_excluded_path('build')
        
        elif primary_language == ProjectLanguage.JAVA:
            project.add_excluded_path('target')
            project.add_excluded_path('build')
            project.add_excluded_path('.gradle')
        
        elif primary_language == ProjectLanguage.CPP or primary_language == ProjectLanguage.C:
            project.add_excluded_path('build')
            project.add_excluded_path('cmake-build-debug')
            project.add_excluded_path('cmake-build-release')
    
    def is_valid_project(self, path: str) -> bool:
        """
        Verifica se um caminho representa um projeto válido para análise.
        
        Args:
            path: Caminho para verificar
            
        Returns:
            True se for um projeto válido, False caso contrário
        """
        try:
            project_path = Path(path)
            
            if not project_path.exists() or not project_path.is_dir():
                return False
            
            # Verifica se há pelo menos um arquivo de código
            code_extensions = {'.py', '.js', '.ts', '.java', '.cpp', '.c', '.php', '.rb', '.go', '.rs', '.cs'}
            
            for ext in code_extensions:
                if list(project_path.glob(f"**/*{ext}")):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def get_project_info(self, path: str) -> Dict[str, Any]:
        """
        Retorna informações básicas sobre um projeto sem criar o objeto completo.
        
        Args:
            path: Caminho do projeto
            
        Returns:
            Dicionário com informações básicas
        """
        try:
            project_path = Path(path).resolve()
            
            if not self.is_valid_project(str(project_path)):
                return {'valid': False, 'error': 'Não é um projeto válido'}
            
            name = self._detect_project_name(project_path)
            primary_language = self._detect_primary_language(project_path)
            target_languages = self._detect_target_languages(project_path)
            
            return {
                'valid': True,
                'name': name,
                'path': str(project_path),
                'primary_language': primary_language.value,
                'target_languages': [lang.value for lang in target_languages],
                'size_mb': sum(f.stat().st_size for f in project_path.rglob('*') if f.is_file()) / (1024 * 1024)
            }
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}


def detect_project(path: str) -> Project:
    """Factory function para detecção rápida de projeto"""
    detector = ProjectDetector()
    return detector.detect_project(path)