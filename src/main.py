import click
from rich.console import Console

console = Console()


# Cria um grupo de subcomandos com o nome principal sendo a def abaixo, ou seja nesse caso cli
@click.group
@click.version_option(version="1.0.0")
def cli():
    """Code Vulnerability Analysis System"""
    pass

@cli.command()
@click.argument('target', type=click.Path(exists=True)) # Torna obrigatório passar o caminho do código para a CLI executar
@click.option('--language', '-l', help='Programming Language')
@click.option('--format', '-f', default='console', help='Output format')
@click.option('--output', '-o', help='Output file')
def scan(target, language, format, output):
    """Execute Scan"""
    # NO MOMENTO O CÓDIGO SÓ MOSTRA O QUE RECEBEU
    console.print("🔍 [bold blue]Comando SCAN executado![/bold blue]")
    console.print(f"📁 Target: {target}")
    console.print(f"🔤 Language: {language or 'auto-detect'}")
    console.print(f"📄 Format: {format}")
    console.print(f"💾 Output: {output or 'console'}")
    console.print("⚠️ [yellow]Implementação pendente...[/yellow]")

@cli.command()
@click.option('--category', help='Filter by category')
@click.option('--language', help='Filter by language')
def list_rules(category, language):
    """List available security rules"""
    # LISTA REGRAS DE SEGURANNAÇA
    console.print("📋 [bold green]Regras Disponíveis:[/bold green]")
    console.print("• SQL Injection (Python) - HIGH")
    console.print("• XSS Detection (JavaScript) - MEDIUM")
    console.print("• Buffer Overflow (C++) - CRITICAL")
    console.print("⚠️ [yellow]Lista fictícia - implementação pendente...[/yellow]")

if __name__ == '__main__':
    cli()

