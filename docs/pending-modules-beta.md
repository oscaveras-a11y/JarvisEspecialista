# Pendências integradas para o beta pessoal

Desenvolvimento e testes somente no GitHub. Nada precisa ser instalado no computador do proprietário. O beta continua sem login adicional da aplicação; o acesso ao GitHub não autentica identidades declaradas nos relatórios técnicos.

## Testar pelo GitHub

Na aba Actions, “Pending modules validation” executa contratos e demonstrações com arquivos sintéticos em Windows e Linux. Use “Run workflow” na main após a integração. “Real external backends” testa Ghidra e Binwalk reais em Linux.

Esses workflows não são um serviço de upload de casos reais e não preservam um banco operacional entre runners. Nenhum arquivo real de cliente, banco de casos, candidata, senha ou chave deve ser publicado como artefato do CI.

## Recuperação

- assess-recovery CASE CAMINHO: triagem de formato, metadados e hash, sem promessa de recuperação.
- keys inspect CAMINHO: metadados de chave/certificado em processo limitado; não cria banco operacional.
- keys scan CASE DIRETORIO: inventário de metadados somente no diretório autorizado para recuperação, com resultado persistente no relatório.

As sessões recebem somente candidatas fornecidas pelo proprietário, dentro do escopo autorizado. Não fazem geração universal de chaves, consulta a cofres, varredura de outras contas ou busca na rede.

    cyber recovery-session start CASE ARQUIVO --candidates CAMINHO --mode ccaes1
    cyber recovery-session work CASE SESSAO --max-attempts 20 --max-seconds 30
    cyber recovery-session show CASE SESSAO
    cyber recovery-session list CASE
    cyber recovery-session pause CASE SESSAO
    cyber recovery-session resume CASE SESSAO
    cyber recovery-session cancel CASE SESSAO
    cyber recovery-session extend CASE SESSAO --priority --hours 24 --reason "Prioridade declarada pelo operador"

CCAES1: uma chave candidata de 32 bytes, codificada como 64 caracteres hexadecimais por linha. O arquivo deve ter sido fornecido/autorizado pelo proprietário. Saída somente após autenticação GCM, SHA-256 e verificação do claim. Sem chave correta ou fonte recuperável dela não existe reconstrução geral do AES a partir do texto cifrado.

ssh-private: uma senha UTF-8 por linha, preservando espaços. Valida a estrutura com a candidata, sem exportar a chave privada descriptografada nem revelar a senha encontrada. Senha perdida e chave privada perdida são problemas diferentes. Material ausente continua dependendo de cópia legítima. Os modos adicionais `zip`, `7z`, `pdf`, `office` e `pkcs12` validam candidatas em processos limitados; veja [cobertura, ferramentas e limites](recovery-multiformat.md). Eles confirmam a candidata, sem exportar senha ou arquivo desbloqueado. RAR e formatos proprietários continuam sem backend validado.

Limites: alvo de até 8 MiB (também limitado pelo CORE), candidatas até 8 MiB, 100000 linhas e 1024 bytes por linha, sem linhas vazias. Inspeção de chaves: 1 MiB. Biblioteca cryptography com suporte SSH/bcrypt. RSA mantém validação estrutural padrão; parsers e tentativas rodam em processo filho limitado. Não se executa o arquivo analisado.

Janela inicial de 24 horas de relógio; pausa também consome a janela. Lista esgotada encerra o trabalho antes do prazo. Extensão por prioridade exige motivo, até 24h por extensão e teto acumulado de 30 dias; não prorroga nem substitui a autorização do caso. Cada chamada work processa uma fatia de até 300s/1000 tentativas; checkpoints permitem continuar em outro processo no mesmo armazenamento autorizado.

Timeout/falha de recursos em uma tentativa gera resource_limited, sem repetição automática. Para decidir conscientemente tentar novamente, use resume com --reason. A candidata corrente não é pulada silenciosamente. Chaves/senhas não entram em argv, SQLite, auditoria ou relatório. Um HMAC vincula o arquivo de candidatas à sessão, com segredo aleatório local em recovery-material, que precisa ser preservado junto ao armazenamento protegido. Não imprimir, exportar ou versionar esse segredo. Proteger esse armazenamento com as permissões do ambiente operacional; não é um cofre criptografado completo.

Os resultados transitórios ficam em diretório exclusivo por claim. Reserva de publicação é auditada antes da publicação final; claims interrompidos são reconciliados antes de perder sua identidade de limpeza. Estado, contadores e resultados exibidos são conferidos contra a auditoria. Auditoria encadeada não é assinatura digital nem armazenamento imutável.

Um job hospedado pelo GitHub tem limite de seis horas: uma janela de 24h não significa um job contínuo de 24h. Operação real prolongada requer armazenamento durável autorizado e continuidade entre trabalhadores; essa infraestrutura não foi provisionada neste beta. [Limites oficiais](https://docs.github.com/en/enterprise-cloud%40latest/actions/reference/limits).

## Ferramentas adicionais por formato

    cyber recovery-formats
    cyber recovery-session start CASE ARQUIVO --candidates LISTA --mode auto

O inventário distingue suporte implementado e dependência disponível. O ambiente remoto usa o extra `recovery`; “Multi-format recovery validation” instala e testa esse extra nos runners Windows/Linux. `auto` seleciona pelo cabeçalho; PFX/P12 exige `--mode pkcs12`. ZIP cobre ZipCrypto/WinZip AES; 7z cobre conteúdo e cabeçalho protegidos; PDF usa o verificador Standard; Office cobre OOXML Agile/Standard, não os formatos binários antigos; PKCS12 valida chaves/certificados. Nem todo esquema/variante dessas famílias é compatível.

Arquivos sem senha não confirmam uma candidata arbitrária. Novos modos não extraem arquivos em disco nem exportam chaves privadas; conteúdo de ZIP/7z/Office é lido apenas para verificar integridade, dentro de limites. PDF confirma senha, sem declarar integridade/renderização completa. Falha de parser, recursos ou dependência não equivale a senha descoberta. Todas as regras de autorização, checkpoint, pausa e cancelamento continuam aplicadas.

## Inventários de perícia e protocolo

    cyber inventory-disk CASE IMAGEM
    cyber inventory-pcap CASE CAPTURA

Analisam cópia verificada e persistem inventário, hash e referência de evidência no relatório. Disco: MBR/GPT e limites documentados, sem montagem ou recuperação de apagados. PCAP clássico: Ethernet/IPv4/TCP/UDP, sem captura ativa, remontagem de fluxos ou PCAPNG. Não equiparar esses inventários a uma suíte forense profissional completa.

## Dois agentes

    cyber agent-jobs enqueue CASE --agent codex --allow-cloud-summary
    cyber agent-jobs run CASE TRABALHO
    cyber agent-jobs enqueue CASE --agent claude --depends-on TRABALHO_CODEX --allow-cloud-summary
    cyber agent-jobs run CASE TRABALHO_CLAUDE
    cyber agent-jobs list CASE

O segundo agente revisa a proposta do primeiro sobre o mesmo snapshot de evidências. As propostas são persistentes e reconstruíveis no relatório; não resolvem automaticamente a investigação. Só metadados derivados permitidos são enviados. Falhas após envio podem ser incertas e exigir decisão explícita antes de nova chamada, inclusive quanto a possível cobrança.

O proprietário informou que ainda não cadastrou as credenciais. Portanto, a comunicação real não está validada. Em Settings → Secrets and variables → Actions, ele deverá cadastrar CYBER_CODEX_API_KEY e CYBER_ANTHROPIC_API_KEY, sem enviá-las ao chat ou ao código. Não foram criadas credenciais, lidos seus valores ou efetuadas chamadas reais neste trabalho.

Depois disso, “Agent broker manual provider smoke”, opção both e confirmação de chamada real, exercita um caso sintético. Esse teste pode consumir uso dos provedores. A autenticação desses programas é separada desta conversa e não exige criar login adicional para o beta. Testes offline usam contratos/controladores sintéticos e não comprovam credenciais, acesso a modelos ou comunicação real.
