# Memória local de programação segura

O Jarvis inclui uma base de referência offline em português para apoiar revisão de código e remediação. Nesta etapa ela não chama Qwen3, Ollama, serviços de nuvem ou ferramentas de ataque. O índice não lê código do usuário nem conversas.

## Conteúdo

Dezoito guias abordam revisão segura, Python, JavaScript/TypeScript, validação, SQL, comandos, XSS, autenticação, autorização, segredos, dependências, APIs expostas, uploads, caminhos de arquivos, desserialização, logs, criptografia e testes seguros. Cada guia orienta revisão, evidência, correção, regressão e limites; usa dados sintéticos e aponta fontes oficiais.

## Uso

```text
cyber knowledge index
cyber knowledge search "autorização por objeto"
cyber knowledge search "parâmetros SQL" --limit 3
```

O índice SQLite FTS5 fica separado do banco de casos: Windows em `%LOCALAPPDATA%/CyberCore/knowledge.sqlite3`; Unix em `$XDG_DATA_HOME/cyber-core/knowledge.sqlite3` ou `~/.local/share/cyber-core/knowledge.sqlite3`. `--db CAMINHO` seleciona um arquivo alternativo em ambos os comandos. Reexecutar `index` substitui o conteúdo indexado pelo corpus distribuído.

A consulta aceita de 1 a 256 caracteres e no máximo 10 resultados. O texto é tratado como consulta, não como sintaxe SQL; termos encontrados são escapados e passados por parâmetro. O corpus não é sincronizado com conversas, código local ou dados de campanhas.

## Limites e próxima etapa

O índice melhora a recuperação de contexto estático; não treina pesos, não comprova que uma resposta está correta e não oferece atualização automática da Qwen3. A integração futura deve fornecer resultados como contexto citável, preservar aprovação humana para ações e impedir que conteúdo recuperado seja tratado como instrução privilegiada. Mudanças de integração devem ter avaliação separada antes de alterar o perfil padrão.
