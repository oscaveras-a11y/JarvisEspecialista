# Origem deste conteúdo vendorizado

Este diretório é uma cópia **verbatim, sem modificações**, da skill de
engenharia reversa de terceiros abaixo, trazida para dentro do repositório
para que fique disponível offline (sem depender de instalar um plugin do
Claude Code nem de acesso à internet em tempo de uso).

- **Projeto**: `claude-reverse-engineering-skill`
- **Autor**: EncidXVII (https://github.com/EncidXVII)
- **Repositório**: https://github.com/EncidXVII/claude-reverse-engineering-skill
- **Commit vendorizado**: `9a857bd2ee62bd13aa66b3942bd17c89eabf6b8a` (2026-10-19)
- **Versão declarada**: 2.2.4
- **Licença**: Apache License 2.0 (`LICENSE` nesta pasta, cópia integral da
  original) — a licença permite redistribuição e uso, inclusive modificado,
  mantendo aviso de atribuição e licença.

## Auditoria feita antes de trazer para o repositório (2026-11-02)

Antes de vendorizar, o conteúdo foi lido por completo (todos os scripts,
o `SKILL.md`, as referências, os manifestos `.claude-plugin/`, o workflow de
CI) e verificado com `semgrep` (regras próprias de segurança,
`config/semgrep-rules/python-security.yml`) e `detect-secrets`. Resultado:
nenhum malware, backdoor, chamada de rede oculta, exfiltração ou injeção de
prompt embutida encontrada. Resumo:

- Nenhum servidor MCP, hook ou binário declarado no manifesto do plugin —
  classificação `reach: contained` do catálogo (sem alcance remoto/privilegiado).
- Nenhuma chamada de rede real no código (`socket`/`requests`/`urllib` não
  aparecem como import real, só como texto de detecção de padrões em
  binários analisados).
- Único `subprocess` real é `java -version` (checagem de disponibilidade do
  Ghidra); nenhum `eval`/`exec`/`os.system`/`shell=True` executável.
- `zipfile`/`plistlib` usados só para leitura em memória, nunca
  `.extractall()` — sem risco de zip-slip.
- CI usa só GitHub Actions oficiais + uma action de terceiros conhecida
  (`robinraju/release-downloader`), baixando o Ghidra oficial da NSA com
  SHA-256 fixo e verificado antes de descompactar.
- O próprio `SKILL.md` já instrui isolamento de amostras, nunca executar o
  alvo, usar `python -I`, e tratar texto dentro do binário analisado como
  dado, nunca como instrução (defesa contra prompt injection vinda da
  própria amostra).

## O que isso NÃO inclui

Vendorizar este conteúdo traz só as **instruções e os scripts auxiliares**
(texto Markdown + Python/Java puro, sem dependências de rede). As
ferramentas de engenharia reversa que a skill orienta a usar — Ghidra,
radare2, jadx, Frida, etc. — continuam sendo instaladas e configuradas
separadamente (o projeto já faz isso para o Ghidra/Binwalk em
`scripts/install-beta-tools.sh`); nada aqui as baixa ou instala
automaticamente.

## Próximos passos (ainda não feitos)

- Esta cópia ainda não está conectada a nenhum fluxo de trabalho do CORE —
  é material de referência para a seção 6 (engenharia reversa) do escopo.
- A integração com uma IA offline (Qwen3 via Ollama) para operar esta skill
  e o programa como um todo foi explicitamente deixada para depois,
  conforme decisão do proprietário: só entra quando o treinamento do Qwen3
  estiver pronto.
- Atualizar este diretório por cima de uma nova versão upstream deve
  comparar contra o commit acima (`git diff` entre o conteúdo vendorizado e
  um clone fresco do repositório de origem), não substituir às cegas.
