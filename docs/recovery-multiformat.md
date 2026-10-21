# Recuperação de múltiplos formatos — 21/10/2026

## Requisito e execução
O proprietário pediu ampliar as ferramentas para tentar diferentes tipos de arquivos protegidos. Desenvolvimento, geração de amostras e execução somente no GitHub; sem clone, instalação ou execução no computador do proprietário. A autorização de desenvolvimento cobre esta extensão da seção 7; nenhuma alteração na branch Claude. Não há promessa de recuperar qualquer senha nem de contornar autenticação de programas.

## Decisão
Estender RecoverySessions e seu subprocesso fixo, preservando autorização de recuperação, cópia verificada, hash, HMAC das candidatas, checkpoint, leases, pausa e cancelamento. Bibliotecas opcionais por família, sem comandos fornecidos pelo arquivo/usuário. Senha por stdin; nenhum segredo em argv, SQLite, relatório ou saída. Não enviar arquivos ou senhas a provedores.

## Cobertura desta extensão
- ZIP: pyzipper; ZipCrypto e WinZip AES conforme suporte da biblioteca; exige membro criptografado não vazio, leitura integral dos membros e verificadores CRC/AES.
- 7z: py7zr >=1.1.4; senha de conteúdo e cabeçalhos; exige payload criptografado, CRC por arquivo regular e leitura integral em destinos de memória que descartam o conteúdo. Sem extração em disco.
- PDF: pypdf; validação de senha pelo handler Standard suportado. Verificar senha não equivale a validar/renderizar todo o PDF.
- Office: msoffcrypto-tool; OOXML Agile/Standard, incluindo DOCX/XLSX/PPTX que usem esses esquemas. Valida senha e ZIP descriptografado; integridade HMAC quando Agile. DOC/XLS/PPT binários antigos e bloqueios de edição não são cobertos.
- PKCS12/PFX/P12: cryptography; senha e parsing de chave/certificados. Não exporta chave privada.
- SSH/PEM e CCAES1 preservam os fluxos anteriores.
- RAR, discos criptografados, bases proprietárias e credenciais internas de programas: sem backend validado nesta extensão. Inventário indica indisponibilidade; não simula tentativa ou sucesso.

## Resultado e limites
Novos modos confirmam que uma candidata funciona, sem exportar a senha nem plaintext. O relatório distingue o método de validação. Isso não produz automaticamente um arquivo desbloqueado. Arquivos sem senha não confirmam candidatas arbitrárias.

Alvo até 8 MiB, conforme limite já existente; até 256 membros e 16 MiB descompactados por tentativa. Um processo por tentativa, dentro do teto de tempo/saída existente. Limites de expansão não constituem sandbox de memória/privilégios. Erros de dependência, parsing, formatos não suportados e recursos não são senha encontrada. Erro de tentativa para a sessão como resource_limited e exige decisão explícita de retomada.

## Uso remoto
O ambiente remoto confiável instala o extra recovery (o workflow faz isso no runner).
- cyber recovery-formats: inventário de dependências e suporte.
- cyber recovery-session start CASE ARQUIVO --candidates LISTA --mode zip
- Modos: auto, ccaes1, ssh-private, zip, 7z, pdf, office, pkcs12.
- auto examina bytes, não extensão; DER exige pkcs12 explícito por ser ambíguo.
- Trabalho, pausa, retomada, cancelamento e extensão usam os comandos existentes.

Não publicar arquivos operacionais, listas, senhas, chaves ou bancos reais em Git/Actions. Os workflows só usam fixtures sintéticas temporárias. A integração ao painel é entrega separada.

## Plano e evidências
1. Contratos de senha errada/correta para cada família, arquivo sem senha, truncamento, CLI, pausa e auto; publicados antes da implementação.
2. Observar falha no Actions por modo ainda não implementado.
3. Adicionar validadores e dependências opcionais; integrar apenas sessões/CLI.
4. Suíte completa e demo Windows/Linux; revisão independente; documentar resultados antes de considerar integração.
5. Abrir PR próprio; nenhuma integração automática da main ou da branch Claude.

Baseline negativo: commit 7129c2e09408d7d39e9a2e592a98e090b345a68f, run 39684430382 (Linux): contratos falham com Invalid recovery mode; suíte completa 327 testes, 15 falhas/subtestes, 2 skips. A demo existente passou. Resultados positivos ainda precisam ser confirmados no head final.

## Referências das APIs
- https://github.com/danifus/pyzipper
- https://py7zr.readthedocs.io/en/latest/api.html
- https://pypdf.readthedocs.io/en/latest/user/encryption-decryption.html
- https://msoffcrypto-tool.readthedocs.io/en/latest/
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#pkcs12
