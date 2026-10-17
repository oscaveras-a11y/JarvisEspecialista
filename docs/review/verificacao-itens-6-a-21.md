# Verificação consolidada — itens 6 a 21

Autor: **Claude Code**. Percorrendo de 6 a 21 a pedido do proprietário, no modo
"verificar + implementar lacunas". Itens pares são engenharia do Codex (já
parcialmente prontos): verifico e preencho lacunas de forma aditiva, re-mesclando
a `main` conforme ele entrega. Log atualizado por item.

> Legenda: **[FATO]** existe e verificado · **[LACUNA→feito]** faltava e implementei · **[PENDENTE]** depende de ferramenta externa/decisão/Codex.

## Item 6 — Engenharia reversa (par; Codex) — verificado + 1 lacuna preenchida
- **[FATO]** `reverse_engineering.analyze` (cópia verificada, hash, entropia, assinatura), `firmware` (Intel HEX, Motorola S-record com checksum, cabeçalhos ELF/PE com limites, `compare_firmware`), `automotive` (CAN clássico) — tudo estático, sem execução nem modificação de dispositivo.
- **[FATO]** identificação de arquitetura/máquina em ELF/PE (campo `machine`), cabeçalhos e limites de seções validados.
- **[LACUNA→feito]** **Extração de strings** não existia. Implementada em `reverse_engineering/strings.py` (`Core.extract_strings`, CLI `strings`): runs ASCII e UTF-16LE de um prefixo limitado, com `min_length`/`max_strings`; as strings vão ao operador e a auditoria registra **apenas contagens** (conteúdo de evidência não entra na auditoria).
- **[PENDENTE]** Integração de Ghidra/Capstone/Binwalk (ferramentas externas não instaladas) e desmontagem — declarado pendente (itens pares/Fase 4, com o Codex); não afirmar o que não foi executado.
