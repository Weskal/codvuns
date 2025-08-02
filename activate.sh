#!/bin/bash
# Script para ativar rapidamente o ambiente virtual
source venv/bin/activate
echo "✅ Ambiente virtual CODVUNS ativado!"
echo "📍 Diretório: $(pwd)"
echo "🐍 Python: $(python --version)"
echo "📦 Pip: $(pip --version)"
