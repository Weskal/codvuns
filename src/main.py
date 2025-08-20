#!/usr/bin/env python3
"""
CODVUNS - Code Vulnerability Scanner
CLI Principal com Interface Rica

Para executar: python -m src.main <comando>
"""

import click
import sys
import os
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich import box
import time

# Imports do projeto (relativos para funcionar como módulo)
from .core.scanner import Scanner
from .utils.rule_loader import RuleLoader
from .models.finding import Severity
from config.settings import ConfigManager
from src.models.finding import Severity

console = Console()

def print_banner():
    """Exibe banner do CODVUNS"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║  🛡️  CODVUNS - Code Vulnerability Scanner v1.0.0             ║
║     Análise de Vulnerabilidades para Código Fonte             ║
╚═══════════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold blue")

def format_severity_badge(severity: Severity) -> str:
    """Formata badge de severidade com cores"""
    colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red", 
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "green"
    }
    return f"[{colors.get(severity, 'white')}]{severity.value}[/{colors.get(severity, 'white')}]"

def print_scan_summary(result):
    """Exibe resumo da análise"""
    report = result.report
    stats = result.stats
    
    # Painel com informações gerais
    info_table = Table.grid(padding=1)
    info_table.add_column(style="cyan", justify="right")
    info_table.add_column(style="white")
    
    info_table.add_row("📁 Projeto:", report.target_path)
    info_table.add_row("📊 Arquivos analisados:", str(stats.files_analyzed))
    info_table.add_row("⏭️  Arquivos ignorados:", str(stats.files_skipped))
    info_table.add_row("📏 Linhas escaneadas:", f"{stats.total_lines_scanned:,}")
    info_table.add_row("⚡ Tempo de execução:", f"{stats.execution_time:.2f}s")
    info_table.add_row("🔧 Regras aplicadas:", str(stats.rules_applied))
    
    console.print(Panel(info_table, title="📋 Informações da Análise", border_style="blue"))

def print_security_score(score: float):
    """Exibe score de segurança com formatação rica"""
    from src.utils.scoring import SecurityScoreCalculator
    
    # Usa a classificação do scoring.py
    status_text = SecurityScoreCalculator.get_score_classification(score)
    
    # Escolhe cor baseada no score
    if score >= 90:
        color = "green"
        emoji = "🟢"
    elif score >= 75:
        color = "yellow" 
        emoji = "🟡"
    elif score >= 50:
        color = "orange1"
        emoji = "🟠"
    elif score >= 25:
        color = "red"
        emoji = "🔴"
    else:
        color = "bold red"
        emoji = "💀"
    
    score_text = Text(f"{emoji} {score:.1f}/100", style=f"bold {color}")
    description_text = Text(f"{status_text}", style=f"{color}")
    
    console.print(Panel(score_text, title="🏆 Score de Segurança", border_style=color))
    console.print(Panel(description_text, title="📋 Avaliação", border_style=color))

def print_vulnerabilities_summary(report):
    """Exibe resumo de vulnerabilidades"""
    summary = report.summary
    
    # Tabela de contadores
    count_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
    count_table.add_column("Severidade", style="cyan", width=12)
    count_table.add_column("Quantidade", justify="center", style="white", width=10)
    count_table.add_column("Impacto", style="dim", width=20)
    
    severity_data = [
        (Severity.CRITICAL, summary.critical_count, "Falhas críticas"),
        (Severity.HIGH, summary.high_count, "Alta prioridade"),
        (Severity.MEDIUM, summary.medium_count, "Atenção necessária"),
        (Severity.LOW, summary.low_count, "Baixa prioridade"),
        (Severity.INFO, summary.info_count, "Informativo")
    ]
    
    for severity, count, description in severity_data:
        if count > 0:
            badge = format_severity_badge(severity)
            count_style = "bold red" if count > 5 else "white"
            count_table.add_row(badge, f"[{count_style}]{count}[/{count_style}]", description)
    
    if summary.total_findings == 0:
        count_table.add_row("✅ [green]NENHUMA[/green]", "[green]0[/green]", "[green]Código limpo![/green]")
    
    console.print(Panel(count_table, title=f"🚨 Vulnerabilidades Encontradas ({summary.total_findings} total)", border_style="red" if summary.total_findings > 0 else "green"))

def print_top_findings(findings, limit=10):
    """Exibe top findings detalhados"""
    if not findings:
        return
    
    # Ordena por severidade (crítico primeiro)
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order[f.severity])
    
    findings_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
    findings_table.add_column("Sev", width=8)
    findings_table.add_column("Arquivo", style="cyan", width=25)
    findings_table.add_column("Linha", justify="center", width=6)
    findings_table.add_column("Regra", style="dim", width=20)
    findings_table.add_column("Descrição", width=35)
    
    for finding in sorted_findings[:limit]:
        # Formata caminho do arquivo (só nome + diretório pai)
        file_path = Path(finding.file_path)
        short_path = f"{file_path.parent.name}/{file_path.name}" if file_path.parent.name != "." else file_path.name
        
        # Trunca descrição se muito longa
        message = finding.message[:45] + "..." if len(finding.message) > 45 else finding.message
        
        findings_table.add_row(
            format_severity_badge(finding.severity),
            short_path,
            str(finding.line_number),
            finding.rule_id,
            message
        )
    
    title = f"🔍 Top {limit} Vulnerabilidades" + (f" (de {len(findings)} total)" if len(findings) > limit else "")
    console.print(Panel(findings_table, title=title, border_style="yellow"))

def save_report_to_file(report, output_path: str, format_type: str, target_path: str = ""):
    """Salva relatório em arquivo"""
    try:
        if format_type.lower() == 'json':
            # Função para converter Path objects para strings recursivamente
            def clean_paths_for_json(obj):
                if isinstance(obj, dict):
                    return {k: clean_paths_for_json(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [clean_paths_for_json(item) for item in obj]
                elif hasattr(obj, '__fspath__'):  # É um Path object
                    return str(obj)
                elif hasattr(obj, 'isoformat'):  # É um datetime object
                    return obj.isoformat()
                else:
                    return obj
            
            # Limpa o report_dict antes de serializar
            report_dict = report.to_dict()
            clean_dict = clean_paths_for_json(report_dict)
            
            # Adiciona metadados extras ao relatório
            if target_path:
                metadata = {
                    'target_project': Path(target_path).name,
                    'target_full_path': str(Path(target_path).resolve()),
                    'report_generated_at': datetime.now().isoformat(),
                    'codvuns_version': '1.0.0'
                }
            
            clean_dict = clean_paths_for_json(report_dict)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(clean_dict, f, indent=2, ensure_ascii=False)
                
        elif format_type.lower() == 'csv':
            # Implementação básica CSV
            import csv
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Header com informações do projeto
                if target_path:
                    writer.writerow([f'# Relatório CODVUNS - Projeto: {Path(target_path).name}'])
                    writer.writerow([f'# Gerado em: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
                    writer.writerow([])  # Linha em branco
                
                writer.writerow(['Arquivo', 'Linha', 'Severidade', 'Regra', 'Mensagem'])
                for finding in report.findings:
                    writer.writerow([
                        str(finding.file_path),  # Converte para string explicitamente
                        finding.line_number,
                        finding.severity.value,
                        finding.rule_id,
                        finding.message
                    ])
        
        # Mostra informações sobre o arquivo salvo
        file_size = Path(output_path).stat().st_size
        console.print(f"✅ Relatório salvo em: [cyan]{output_path}[/cyan] ([dim]{file_size} bytes[/dim])")
        
    except Exception as e:
        console.print(f"❌ Erro ao salvar relatório: {e}", style="red")
        
        # Debug: mostra qual campo está causando problema
        try:
            console.print("🔍 Investigando qual campo tem Path object...", style="dim")
            test_dict = report.to_dict()
            for key, value in test_dict.items():
                try:
                    import json
                    json.dumps(value)
                    console.print(f"  ✅ {key}: OK", style="dim")
                except Exception as field_error:
                    console.print(f"  ❌ {key}: {field_error}", style="dim red")
        except Exception as debug_error:
            console.print(f"  Debug falhou: {debug_error}", style="dim red")

# Cria um grupo de subcomandos 
@click.group(invoke_without_command=True)
@click.version_option(version="1.0.0")
@click.pass_context
def cli(ctx):
    """🛡️ CODVUNS - Code Vulnerability Analysis System"""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("Use [cyan]python -m src.main --help[/cyan] para ver comandos disponíveis.\n")
        console.print("Comandos principais:")
        console.print("  • [cyan]python -m src.main scan <caminho>[/cyan]     - Analisa vulnerabilidades")
        console.print("  • [cyan]python -m src.main list-rules[/cyan]         - Lista regras disponíveis")
        console.print("  • [cyan]python -m src.main --version[/cyan]          - Mostra versão")

@cli.command()
@click.argument('target', type=click.Path(exists=True))
@click.option('--language', '-l', help='Linguagem de programação (auto-detect se não especificado)')
@click.option('--format', '-f', default='console', type=click.Choice(['console', 'json', 'csv']), help='Formato de saída')
@click.option('--output', '-o', help='Arquivo de saída (default: console)')
@click.option('--verbose', '-v', is_flag=True, help='Saída detalhada')
@click.option('--quiet', '-q', is_flag=True, help='Saída mínima (apenas resumo)')
@click.option('--max-findings', default=10, help='Máximo de vulnerabilidades detalhadas a exibir')
def scan(target, language, format, output, verbose, quiet, max_findings):
    """🔍 Executa análise de vulnerabilidades em um projeto"""
    
    if not quiet:
        print_banner()
        console.print(f"🎯 Iniciando análise de: [cyan]{target}[/cyan]\n")
    
    try:
        # Configura scanner
        config_manager = ConfigManager()
        scanner = Scanner(config_manager)
        
        # Mostra progresso
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            
            # Tarefas de progresso
            detect_task = progress.add_task("🔍 Detectando projeto...", total=None)
            rules_task = progress.add_task("📋 Carregando regras...", total=None)
            scan_task = progress.add_task("🔬 Analisando código...", total=None)
            
            # Executa análise
            progress.update(detect_task, description="🔍 Detectando projeto...")
            time.sleep(0.1)  # Para mostrar o progresso
            
            progress.update(rules_task, description="📋 Carregando regras...")
            time.sleep(0.1)
            
            progress.update(scan_task, description="🔬 Analisando vulnerabilidades...")
            result = scanner.analyze(target)
            
            progress.update(detect_task, completed=True)
            progress.update(rules_task, completed=True) 
            progress.update(scan_task, completed=True)
        
        console.print("✅ Análise concluída!\n")
        
        # Exibe resultados baseado no formato
        if format == 'console' and not quiet:
            print_scan_summary(result)
            print_security_score(result.report.summary.security_score)
            print_vulnerabilities_summary(result.report)
            
            if result.report.findings and not quiet:
                print_top_findings(result.report.findings, max_findings)
            
            # Mostra erros se houver
            if result.errors and verbose:
                console.print("\n⚠️ Erros durante análise:", style="yellow")
                for error in result.errors[:5]:
                    console.print(f"  • {error}", style="dim")
        
        elif quiet:
            # Saída mínima
            score = result.report.summary.security_score
            findings = result.report.summary.total_findings
            console.print(f"Score: {score:.1f}/100 | Vulnerabilidades: {findings}")
        
        # Salva arquivo se especificado
        if output:
            save_report_to_file(result.report, output, format, target)
        elif format != 'console':
            # Gera nome automático baseado no projeto e timestamp
            from datetime import datetime
            project_name = Path(target).name
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            reports_dir = Path("reports")
            auto_name = reports_dir / f"{project_name}_report_{timestamp}.{format}"
            auto_name = str(auto_name)  # Converte para string
            #auto_name = f"{project_name}_report_{timestamp}.{format}"
            
            console.print(f"💾 Salvando relatório automaticamente como: [cyan]{auto_name}[/cyan]")
            save_report_to_file(result.report, auto_name, format, target)
        
        # Código de saída baseado na análise
        if result.report.summary.critical_count > 0:
            sys.exit(2)  # Crítico
        elif result.report.summary.high_count > 5:
            sys.exit(1)  # Muitas vulnerabilidades altas
        else:
            sys.exit(0)  # OK
            
    except Exception as e:
        console.print(f"❌ Erro durante análise: {e}", style="bold red")
        if verbose:
            import traceback
            console.print(traceback.format_exc(), style="dim red")
        sys.exit(1)

@cli.command()
@click.option('--category', help='Filtrar por categoria (injection, xss, etc.)')
@click.option('--language', help='Filtrar por linguagem (python, javascript, etc.)')
@click.option('--severity', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']), help='Filtrar por severidade')
@click.option('--enabled-only', is_flag=True, help='Mostrar apenas regras habilitadas')
def list_rules(category, language, severity, enabled_only):
    """📋 Lista regras de segurança disponíveis"""
    
    print_banner()
    console.print("📋 [bold cyan]Regras de Segurança Disponíveis[/bold cyan]\n")
    
    try:
        # Carrega regras
        rule_loader = RuleLoader()
        rules_info = rule_loader.list_available_rules()
        rules = rules_info['rules']
        
        # Aplica filtros
        filtered_rules = rules
        
        if category:
            filtered_rules = [r for r in filtered_rules if category.lower() in r.category.value.lower()]
        
        if language:
            filtered_rules = [r for r in filtered_rules if language.lower() in [lang.lower() for lang in r.target_languages]]
        
        if severity:
            from src.models.finding import Severity as SevEnum
            target_severity = SevEnum(severity)
            filtered_rules = [r for r in filtered_rules if r.severity == target_severity]
        
        if enabled_only:
            filtered_rules = [r for r in filtered_rules if r.enabled]
        
        # Cria tabela de regras
        rules_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        rules_table.add_column("ID", style="cyan", width=20)
        rules_table.add_column("Nome", style="white", width=25)
        rules_table.add_column("Sev", width=8)
        rules_table.add_column("Categoria", style="yellow", width=15)
        rules_table.add_column("Linguagens", style="green", width=15)
        rules_table.add_column("Status", width=8)
        
        for rule in filtered_rules:
            languages = ", ".join(rule.target_languages[:2])  # Primeiras 2 linguagens
            if len(rule.target_languages) > 2:
                languages += "..."
            
            status = "✅" if rule.enabled else "❌"
            
            rules_table.add_row(
                rule.id,
                rule.name[:25] + "..." if len(rule.name) > 25 else rule.name,
                format_severity_badge(rule.severity),
                rule.category.value,
                languages,
                status
            )
        
        console.print(rules_table)
        
        # Estatísticas
        console.print(f"\n📊 Mostrando [cyan]{len(filtered_rules)}[/cyan] de [cyan]{len(rules)}[/cyan] regras disponíveis")
        
        if rules_info['by_category']:
            console.print(f"📂 Categorias: {', '.join(rules_info['by_category'].keys())}")
        
        if rules_info['by_language']:
            console.print(f"💻 Linguagens: {', '.join(rules_info['by_language'].keys())}")
        
    except Exception as e:
        console.print(f"❌ Erro ao carregar regras: {e}", style="red")
        sys.exit(1)

@cli.command()
@click.argument('project_path', type=click.Path(exists=True))
def info(project_path):
    """ℹ️  Mostra informações sobre um projeto sem analisar vulnerabilidades"""
    
    print_banner()
    console.print(f"ℹ️  [bold cyan]Informações do Projeto[/bold cyan]\n")
    
    try:
        from src.core.project_detector import ProjectDetector
        
        detector = ProjectDetector()
        project_info = detector.get_project_info(project_path)
        
        if not project_info['valid']:
            console.print(f"❌ {project_info['error']}", style="red")
            return
        
        # Cria tabela de informações
        info_table = Table.grid(padding=1)
        info_table.add_column(style="cyan", justify="right")
        info_table.add_column(style="white")
        
        info_table.add_row("📁 Nome:", project_info['name'])
        info_table.add_row("📍 Caminho:", project_info['path'])
        info_table.add_row("🔤 Linguagem principal:", project_info['primary_language'])
        info_table.add_row("💻 Linguagens encontradas:", ", ".join(project_info['target_languages']))
        info_table.add_row("📊 Tamanho:", f"{project_info['size_mb']:.2f} MB")
        
        console.print(Panel(info_table, title="📋 Detalhes do Projeto", border_style="blue"))
        
        console.print(f"\n✅ Projeto válido para análise com CODVUNS!")
        
    except Exception as e:
        console.print(f"❌ Erro ao analisar projeto: {e}", style="red")

if __name__ == '__main__':
    cli()