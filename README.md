# CODVUNS - Code Vulnerability Scanner

Um scanner de vulnerabilidades para código fonte desenvolvido como TCC.

## Instalação

1. Execute o script de setup:
```bash
bash setup_codvuns.sh
```

2. Ative o ambiente virtual:
```bash
source venv/bin/activate
```

3. Execute os testes:
```bash
pytest tests/
```

## Uso

```bash
python -m src.main --help
```

## Estrutura do Projeto

```
codvuns/
├── src/
│   ├── core/          # Núcleo do sistema
│   ├── analyzers/     # Analisadores de código
│   ├── rules/         # Regras de vulnerabilidades
│   ├── utils/         # Utilitários
│   └── models/        # Modelos de dados
├── tests/             # Testes
├── config/            # Configurações
├── reports/           # Relatórios gerados
└── docs/              # Documentação
```
