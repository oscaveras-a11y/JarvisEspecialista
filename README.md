# CYBER CORE

Plataforma local de investigação tecnológica **autorizada**, em desenvolvimento. Python 3.12+, SQLite, Windows, sem GPU dedicada. Repositório privado J.A.R.V.I.S reutilizado por autorização do proprietário, com histórico anterior preservado.

**Entrega atual:** Fase 1 e protótipo inicial de investigação. Não é a plataforma completa. Veja [estado das fases](docs/roadmap.md), [limites de segurança](docs/security.md) e [validação real](docs/validation.md).

## Instalação no Windows

```powershell
git clone https://github.com/oscaveras-a11y/J.A.R.V.I.S.git
Set-Location J.A.R.V.I.S
.\scripts\install.ps1 -Python python
.\.venv\Scripts\cyber.exe doctor
.\.venv\Scripts\cyber.exe --help
```

Se Python não estiver no PATH, passe `-Python 'C:\caminho\python.exe'`. O instalador cria um venv local e instala `cryptography`, a única dependência de runtime. Não instala Codex, Claude nem suítes externas. A política de execução de scripts do computador deve permitir os scripts; não é modificada automaticamente.

Alternativa sem instalação do pacote, usando um Python com cryptography disponível:

```powershell
$env:PYTHONPATH = Join-Path $PWD 'src'
python -m cyber_core doctor
python -m cyber_core --help
```

## Primeira investigação

Escolha uma pasta de arquivos autorizados fora do checkout. O armazenamento padrão é `%LOCALAPPDATA%\CyberCore`. Use um `CYBER_HOME` distinto por cliente e ACLs adequadas. Operações em diretórios Git e caminhos de rede são rejeitadas para armazenamento.

```powershell
$env:CYBER_HOME = Join-Path $env:LOCALAPPDATA 'CyberCore\cliente-demo'
$cyber = '.\.venv\Scripts\cyber.exe'
& $cyber init
& $cyber investigate --project laboratorio --objective 'Identificar binário próprio' --scope 'C:\Laboratorio\entradas' --owner 'Responsavel' --authorization 'Autorizacao de bancada sobre arquivos sinteticos'
# Copie o id retornado:
& $cyber analyze-file ID 'C:\Laboratorio\entradas\amostra.bin'
& $cyber status ID
& $cyber report ID
```

A autorização declarada vale 24 horas por padrão, configurável por `--valid-hours`; `cyber revoke ID` a revoga. O operador é responsável pela legitimidade da declaração. A plataforma não verifica uma identidade legal.

`analyze-file` preserva o original, cria uma cópia exclusiva verificada, calcula SHA-256, mede entropia por fluxo e identifica assinaturas conhecidas. Uma assinatura ELF não valida estruturas ELF; entropia alta não comprova criptografia. Cada resultado gera hipótese aberta, proposta de experimento e checkpoint persistente. A investigação permanece EM INVESTIGACAO; não é declarada resolvida automaticamente.

## Fila, pausa e retomada

```powershell
& $cyber analyze-file ID 'C:\Laboratorio\entradas\amostra.bin' --queue-only
& $cyber pause ID
# Pode encerrar o terminal. Em outro terminal, restaure CYBER_HOME:
& $cyber resume ID
& $cyber run ID
```

`run` executa uma tarefa pendente; não é um daemon. Claims transacionais e leases impedem duplicação de resultados no banco. Após morte do processo, tarefas em execução podem ser retomadas após o vencimento do lease (timeout + 30 segundos), até três tentativas. Falha definitiva registra erro e não fica repetindo. Pausa ocorre entre operações, sem interromper uma aquisição já iniciada. Cancelamento/worker gerenciado e retomada automática após boot ainda estão pendentes.

## AES-256 autorizado

Somente o envelope de laboratório `CCAES1` é suportado: magic de 6 bytes, nonce de 12 bytes, ciphertext e tag GCM de 16 bytes, com o magic como AAD. Não há suporte universal a arquivos AES, ZIP, BitLocker ou firmware. Não há quebra de AES ou busca indiscriminada de senhas.

Registre a investigação com `--allow-recovery`, além do escopo e autorização. A chave deve estar em arquivo local protegido contendo exatamente **32 bytes brutos**, fora do Git. Não passe a chave na linha de comando.

```powershell
& $cyber recover-aes ID 'C:\Laboratorio\entradas\arquivo.ccaes' --key-file 'C:\Cofre\material.key' --expected-sha256 HASH_DO_PLAINTEXT --expected-format 'PDF signature'
```

Três tentativas criptográficas por investigação; entrada limitada a 64 MiB ou ao limite configurado menor. A tag é autenticada antes de escrever plaintext. Falhas de chave, integridade ou autorização não produzem saída recuperada. Chaves não são persistidas: a auditoria registra referência opaca ao material fornecido. As expectativas de hash e formato são opcionais; a autenticação GCM é sempre obrigatória. Python não garante zerar todas as cópias de uma chave na memória.

## Agentes

`cyber agents` e `cyber doctor` descobrem CLIs, sem assumir autenticação. O núcleo funciona sem agentes. O adaptador inicial Codex usa processo com stdin estruturado, sandbox read-only, tempo e saída limitados. A saída é proposta, não comando. A chamada real falhou no sandbox e uma segunda tentativa sob o usuário correto excedeu o timeout; a integração autenticada permanece não validada.

`cyber review ID --allow-cloud-summary` envia somente tamanho, formato, entropia e estado de verificação ao Codex. Não envia caminhos, conteúdo, objetivo ou autorização. Exige permissão explícita de envio e limita a cinco chamadas por investigação; isso **não** é um limite financeiro garantido. O sandbox do CLI é uma dependência externa, não um isolamento implementado pelo CYBER CORE.

Claude tem interface extensível e diagnóstico, mas sua execução é bloqueada até o CLI e o contrato serem validados. Worktrees por tarefa, paralelismo e revisão cruzada automatizada completa ainda não foram implementados.

## Testes e demonstração

```powershell
.\scripts\test.ps1 -Python '.\.venv\Scripts\python.exe'
# Ou:
$env:PYTHONPATH = Join-Path $PWD 'src'
python -m unittest discover -s tests -v
python scripts/demo.py
```

A demonstração gera todos os arquivos sintéticos e uma chave aleatória em memória, preserva o relatório em diretório temporário e imprime os resultados. Não utiliza dados de clientes. `scripts/agent-smoke.py` é opcional, realiza chamada real ao Codex com resumo sintético e pode consumir a cota do agente; não faz parte da suíte offline.

Os comandos `analyze-firmware`, `analyze-can`, `forensic` e `research` serão publicados quando suas implementações reais estiverem testadas; hoje são rejeitados como comandos desconhecidos. Não existem integrações fictícias com Ghidra, Autopsy, Nmap ou outras ferramentas.
