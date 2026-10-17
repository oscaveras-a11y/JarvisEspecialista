# Item 7 — Criptografia e recuperação: verificação e incremento

Autor: **Claude Code** (item ímpar 7). Data: 2026-10-17.

## Conformidade com o escopo (item 7)

| O escopo pede | Estado | Onde |
|---|---|---|
| Identificar formatos criptografados | **[FATO]** | `cryptanalysis/assessment.py` (assinaturas), `differentiate` |
| Diferenciar criptografia / compressão / ofuscação / codificação | **[IMPLEMENTADO AGORA]** | `cryptanalysis/differentiate.py` |
| Analisar cabeçalhos, calcular entropia | **[FATO]** | `reverse_engineering.analyze`, `assessment`, `differentiate` |
| Examinar metadados, formatos proprietários | **[FATO/PARCIAL]** | `assessment` (ZIP/PDF/OLE/LUKS/openssl/7z/rar) |
| Verificar integridade de arquivos | **[FATO]** | cópia verificada + SHA-256 (`verification/artifacts`) |
| Trabalhar com chaves fornecidas legitimamente | **[FATO]** | `recover-aes` (CCAES1 + chave de 32 bytes) |
| Recuperação de senha de arquivo próprio/autorizado, com controles | **[FATO]** | `self-test-recovery` + `make-lab-envelope` (CCPW1), limites e auditoria |
| Avaliar possibilidades reais de recuperação | **[FATO]** | `assess-recovery` (rotas + limitações) |
| Documentar limitações | **[FATO]** | todos os módulos retornam limitações explícitas |
| Não presumir que alta entropia = criptografia | **[FATO]** | `differentiate` marca "high-entropy / indistinguível" e registra a limitação |
| Não incluir extração clandestina de chaves / acesso não autorizado | **[FATO]** | por design; recuperação exige chave/senha e autorização |
| AES/RSA/ECC/ChaCha20 | **[PARCIAL]** | AES-GCM real; RSA/ECC/ChaCha reconhecidos por assinatura quando houver, sem quebrar |

## Incremento desta sessão — diferenciação estática

`cryptanalysis/differentiate.py` (`Core.differentiate_content`, CLI `differentiate`): classifica um prefixo limitado como **encoding** (hex/base64), **compression** (gzip/xz/bzip2), **archive** (zip/7z/rar), **encrypted** (CCAES1/CCPW1/LUKS/openssl/PGP/age — por assinatura declarada), **text**, **high-entropy** (criptografado **ou** comprimido, indistinguível) ou **structured**. Honesto por construção: entropia alta nunca é afirmada como criptografia; assinatura é observação, não validação de formato; só o prefixo é inspecionado.

Execução local (Linux/3.13): **172 testes OK** (165 + 7 de diferenciação), `compileall` e `demo.py` (exit 0); CLI `differentiate` disponível.

## Pendências do item 7 (coordenar com o Codex / itens pares)
- Reconhecimento/validação mais profundos por família (RSA/ECC/ChaCha) e parsers íntegros — sobrepõe engenharia reversa (item 6, par) e integração de ferramentas externas (itens pares/Fase 4).
- Recuperação de arquivos **danificados** (reparo de formato) além da triagem — exige parsers por formato.
- Exigir `authorization_basis` nas recuperações com chave (`recover-aes`) além do autoteste — passo de núcleo (item 14), a decidir com o Codex.
