# CODVUNS - Code Vulnerability Analysis System

Scanner de vulnerabilidades para código fonte desenvolvido como Trabalho de Conclusão de Curso (TC)

O CODVUNS (Code Vulnerability Scanner) é uma ferramenta de análise estática de segurança projetada para identificar vulnerabilidades em código fonte de forma automatizada. O projeto combina técnicas de análise de padrões (regex), análise sintática (AST) e machine learning para detectar falhas de segurança com alta precisão.

## Principais Objetivos

- Detectar vulnerabilidades comuns como SQL Injection, XSS, hardcoded secrets, entre outras
- Suporte multi-linguagem (Python, JavaScript, Java, C++, etc.)
- Relatórios detalhados em múltiplos formatos (console, JSON, HTML, YAML)
- Sistema de cálculo de score por projeto 

## Diferenciais

- Baixo falso positivo através de análise contextual
- Configuração flexível podendo ser padrão global ou definida pelo usuário por projeto
- Interface CLI intuitiva com feedback visual
- Arquitetura extensível para novas regras e linguagens
- Performance otimizada com processamento paralelo

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
