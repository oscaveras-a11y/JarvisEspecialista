# Ampliação de recuperação: RAR5

Base: PR #24, commit 3ab10856366c12087f36090cf10d3717524e2f80. Desenvolvimento e testes
somente no GitHub, sem alterar a branch Claude. Autorização: ampliar a cobertura
de recuperação, preservando a consulta explícita da senha confirmada.

## Contrato
- Modos rar5 (verificador nativo, Windows/Linux) e john-rar5 (John Jumbo/rar2john, Linux).
- RAR5 com verificador de senha: dados protegidos ou cabeçalhos protegidos.
- PBKDF2-SHA256 do formato, com CRC32 dos cabeçalhos e checksum SHA-256 do
  verificador conferidos. O perfil John compara todos os hashes do conversor
  com os parâmetros lidos independentemente dos bytes originais.
- Arquivos com metadados visíveis exigem que a candidata satisfaça todos os
  verificadores de arquivos encontrados; cabeçalhos protegidos confirmam o
  verificador global dos cabeçalhos, sem inspecionar membros cifrados.
- Sem descriptografia, extração ou exportação de arquivos. O resultado declara
  payload_integrity_verified=false; confirmar senha não comprova payload íntegro.
- Preservar pausa, cancelamento, autorização, HMAC, auditoria, checkpoints e
  show --show-password. Não gravar senhas em resultados padrão ou relatórios.

## Limites
8 MiB de alvo, 256 arquivos, 1024 blocos, 256 verificadores e KDF log2 até 20;
orçamento agregado de 2^22 iterações por candidata. Metadados visíveis: até
16 MiB declarados expandidos. Cabeçalhos cifrados não permitem conferir esse
tamanho sem descriptografia. Não há descompressão neste perfil.
RAR4, SFX, multipartes identificáveis em metadados visíveis, verificadores ausentes
e versões de criptografia não reconhecidas são recusados. Cabeçalhos cifrados
confirmam somente seu verificador global: não determinam volumes, membros ou senhas
individuais do conteúdo. Sem promessa de reparo ou recuperação universal.

## Plano de implementação
1. Publicar contratos negativos e workflow com fixtures RAR5 reais geradas no runner.
2. Implementar parser limitado/verificador nativo e integração nas sessões.
3. Integrar rar2john com perfis fechados, SHA-256 e validação independente.
4. Rodar fixtures reais de dados/cabeçalhos, comprimidos/armazenados, senhas
   incorretas/corretas, listas esgotadas, mistura de senhas e metadados danificados.
5. Suítes Windows/Linux, combinação temporária fixada e revisão estática Claude;
   registrar recibos no PR, sem merge automático.

RAR CLI é instalado apenas no runner para produzir fixtures sintéticas; não é
dependência do produto e não é redistribuído. Seu uso de avaliação e licença
permanecem os do pacote Ubuntu. Só dados inventados são usados no CI.

Referências: https://www.rarlab.com/technote.htm e UnRAR crypt5.cpp;
John Jumbo rar5_fmt_plug.c e rar2john.c no commit fixado pelo PR #24.
