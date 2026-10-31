# Recuperação ampla sem chave como pré-requisito

Requisito atualizado pelo proprietário: atender múltiplos tipos de arquivos; o cliente fornece autorização e escopo, sem depender de chave fornecida. A entrada agora é uma triagem reproduzível de arquivo ou lote. O parecer não é uma promessa de recuperação.

## Triagem e tentativas de senha são operações distintas

As tabelas abaixo descrevem `assess-recovery`, que continua sendo triagem por prefixo e não tenta senhas. O fluxo separado `recovery-session` acrescenta validadores para ZIP, 7z, PDF, OOXML e PKCS12, além dos anteriores; veja [formatos, ferramentas e verificações](recovery-multiformat.md). Esses modos confirmam candidatas fornecidas pelo proprietário e não exportam senha nem arquivo desbloqueado. RAR e variantes não suportadas não devem ser anunciados como recuperáveis.

## Cobertura comprovável desta entrega

| Família | Implementado | Não demonstrado |
|---|---|---|
| ZIP e contêineres compatíveis | Assinatura e primeiro cabeçalho local; flag de criptografia e campo AES quando íntegro no prefixo | Validação de todos os membros, OOXML/ODF completo, extração, recuperação de senha |
| PDF | Assinatura e marcador /Encrypt como indício não conclusivo | Parser de trailer/xref, permissões e recuperação |
| OLE/CFB | Assinatura e possíveis nomes de streams de criptografia como indícios | Parser de diretório, validação de Office e recuperação |
| 7z e RAR4/RAR5 | Reconhecimento de assinatura | Parser de cabeçalhos, volumes, criptografia ou reparo |
| LUKS | Assinatura e versão declarada quando presente | Validação de header/keyslots, montagem e recuperação |
| Envelope OpenSSL Salted__ | Reconhecimento de assinatura | Determinação de algoritmo/KDF, senha ou recuperação |
| SQLite, ELF, DOS/PE, gzip, PNG/JPEG | Reconhecimento de assinatura e classificação por família | Integridade estrutural e reparo desses formatos |
| CCAES1 | Reconhecimento para triagem; descriptografia GCM validada separadamente quando material legítimo existe | Descriptografia sem material ou quebra de AES |
| Formato desconhecido/proprietário | SHA-256, entropia, cópia verificada e roteiro de proveniência/amostras de referência | Identificação garantida, alegação automática de criptografia ou recuperação universal |

Os analisadores leem um prefixo de até 64 KiB da cópia verificada. Não há decomposição de arquivos compactados nem execução de arquivos analisados. Extensão não determina o tipo. Marcadores de PDF/Office podem ser texto comum; assinaturas podem ser falsificadas ou pertencer a arquivos truncados. Um membro ZIP sem flag de criptografia não permite concluir que os demais estejam desprotegidos.

Todos os pareceres expõem `format_validated=false` e `recovery_demonstrated=false`. Declarações de criptografia no cabeçalho são observações, não validação do ciphertext. Entropia alta pode resultar de compressão, aleatoriedade ou outros formatos. A ausência de um marcador no prefixo não comprova ausência de criptografia.

## Fluxo operacional

1. Registrar projeto, responsável, autorização, validade e diretório de escopo, com `--allow-recovery`.
2. Executar `assess-recovery` em arquivo ou pasta, sem argumento de chave.
3. Verificar o parecer e identificar se há hipótese de corrupção, formato não validado, contêiner protegido ou dados insuficientes.
4. Inventariar backups, versões, exportações de recuperação, documentação do fabricante e fontes especificamente autorizadas. Nesta versão, isso é orientação para a investigação; nenhuma varredura clandestina ou automática de cofres é realizada.
5. Escolher e validar o procedimento específico antes de prometer um resultado. Procedimentos ainda ausentes no produto continuam identificados como pendentes.
6. Registrar resultados reproduzíveis e só apresentar recuperação como concluída quando os dados recuperados forem efetivamente validados.

## Limites de lote

Padrão: 100 arquivos, 256 MiB agregados, 64 MiB por arquivo (configurável no limite do núcleo), sem recursão automática. Limites máximos de parâmetros: 1000 arquivos e 1 GiB agregado; enumeração para após 20000 entradas, fila de até 1000 diretórios pendentes ou prazo do núcleo. Links e reparse points são ignorados e contabilizados. Diretórios de dados operacionais não podem se sobrepor à entrada do lote.

A entrada na fila é transacional. Cada tarefa conserva o teto de bytes observado no inventário; crescimento posterior é rejeitado, inclusive ao retomar em outro processo. A execução sequencial compartilha o prazo do núcleo; itens restantes ficam na fila. Erros de pausa, revogação e expiração preservam tarefas pendentes e são reportados como impedimentos. O prazo é cooperativo entre leituras/operações; não é um limite rígido de sistema operacional para I/O bloqueado. Nenhum item é apresentado como recuperado por ter concluído a triagem.

## Produto e expansão

Este fluxo é uma base para qualificação técnica de casos em documentos, arquivos compactados, backups, bancos de dados e binários. Ainda não comprova prontidão comercial, certificação forense, recuperação de arquivos apagados ou resultados em equipamentos reais. As próximas entregas devem priorizar parsers de integridade por família e restauração de cópias autorizadas, seguidas de ensaios reproduzíveis com casos consentidos e representativos. Não incluir um formato em material comercial como recuperável apenas porque sua assinatura é reconhecida.

## Fontes técnicas consultadas em 16/10/2026

- ZIP: [PKWARE APPNOTE 6.3.10](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), cabeçalhos locais, flags e campos extras.
- CFB: [Microsoft MS-CFB, Compound File Header](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea).
- 7z: [documentação de recuperação do 7-Zip](https://www.7-zip.org/recover.html), assinatura e limites de integridade.
- RAR: [RARLAB, RAR 5.0 archive format](https://www.rarlab.com/technote.htm).
- LUKS: [cryptsetup FAQ](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/FAQ.md).
- OpenSSL: [implementação oficial apps/enc.c](https://github.com/openssl/openssl/blob/master/apps/enc.c).
