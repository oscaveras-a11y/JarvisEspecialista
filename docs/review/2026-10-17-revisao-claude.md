# Revisão independente — Claude Code (2026-10-17)

Revisor: agente **Claude Code** (papel de revisão independente e investigação).
Base revisada: `main` em `4150ece` (merge do PR #1 `codex/github-validation`), branch de trabalho `claude/gifted-gates-kd07xv`.
Engenheiro principal das mudanças revisadas: **Codex**.

Esta é a primeira sessão de revisão. O objetivo foi **ler, reproduzir e avaliar** o que já existe — não reescrever o trabalho do Codex. Nada do código-fonte dos módulos foi alterado nesta entrega; o único arquivo adicionado é esta revisão.

> **Classificação das afirmações.** Marco cada ponto como **[FATO]** (verificado por execução ou leitura direta do código nesta sessão), **[INFERÊNCIA]** (deduzido do código, não executado) ou **[HIPÓTESE]** (a confirmar). Isso segue a própria disciplina científica que o sistema impõe.

---

## 1. O que foi reproduzido nesta sessão

Ambiente desta revisão: **Linux**, CPython **3.13.16**, `cryptography` 50.0.2. Importante: **não é** o alvo oficial (Windows / Python 3.12). Os resultados abaixo valem para este ambiente; os resultados Windows continuam sendo os registrados em `docs/validation.md` e no CI.

| Verificação | Comando | Resultado |
|---|---|---|
| Instalação do pacote | `pip install -e .` | **[FATO]** OK — `cyber-core 0.1.0` construído e instalado |
| Compatibilidade de dependências | `pip check` | **[FATO]** `No broken requirements found` |
| Compilação | `compileall -q src scripts tests` | **[FATO]** OK |
| CLI instalada | `cyber --help` | **[FATO]** OK — 21 subcomandos expostos |
| Suíte de testes | `python scripts/run-tests.py` | **[FATO]** **94 testes, OK, 0 falhas/erros/skips**, 5,365 s |
| Demonstração sintética | `python scripts/demo.py` | **[FATO]** exit 0, `platform_complete: false` |

**Corroboração de honestidade [FATO].** Os hashes da demo batem *exatamente* com os registrados em `docs/validation.md`:

- Binário sintético: SHA-256 `1f1b0fd44bfd8ac41cefa1de8dd28989adcb25acf1f972fee97feebc5504ba58`, entropia `7.999999324684831`.
- Plaintext recuperado (CCAES1): 40 bytes, SHA-256 `d886ecb5a92f302d5530a7dfd7da2d73a41f197d903aab8f952cb4ea71c8ea72`.

Ou seja: a contagem de 94 testes e os artefatos documentados pelo Codex são **reprodutíveis e verdadeiros**. Como observação adicional **[FATO]**, a suíte passou inteira em Linux/3.13 — o código é mais portável do que o alvo Windows sugere (os pontos específicos de Windows estão guardados por `os.name == 'nt'` e `getattr(..., 'st_file_attributes', 0)`).

---

## 2. O que está realmente implementado (não é esqueleto)

Leitura direta dos módulos **[FATO]**. Não há diretórios vazios "de enfeite": cada pasta de módulo tem código real, e o único arquivo essencialmente vazio é um `__init__` de pacote.

- **`core`/`service.py`** (orquestrador real): registro de investigação, autorização revogável com prazo, fila de tarefas com *leases*, tentativas limitadas, checkpoints, pausa/retomada, relatórios.
- **`memory`**: esquema SQLite versionado (v1→v3, aditivo), **trilha de auditoria encadeada por SHA-256** com serialização `BEGIN IMMEDIATE` antes de ler o predecessor da cadeia (cuidado real com concorrência).
- **`permissions`**: validação de caminho rejeitando UNC/device, ADS (`:`), traversal (`..`), symlinks e reparse points; proíbe armazenamento operacional dentro de árvore Git.
- **`reverse_engineering`**: cópia verificada (hash do original vs. cópia relida), detecção de mudança do original durante aquisição (`fstat` antes/depois), entropia, identificação de assinatura.
- **`cryptanalysis`**: recuperação AES-256-GCM **apenas** do envelope sintético `CCAES1` com chave fornecida (`recover`); triagem estática sem chave (`assess`/`intake`) com reconhecimento de ZIP/AE-x, PDF `/Encrypt`, OLE-CFB, LUKS, OpenSSL `Salted__`, 7z/RAR etc., sempre marcando `recovery_demonstrated: false`.
- **`firmware`**: parsers Intel HEX e Motorola S-record com checksum, teto de bytes decodificados, e verificação **só de cabeçalhos/limites** de ELF/PE (escopo declarado no próprio retorno).
- **`automotive`**: análise/comparação offline de logs CAN clássicos.
- **`investigation/workflow.py`** (o módulo mais denso, 316 linhas): ciclo científico completo — hipóteses versionadas, experimentos com asserções falsificáveis como *dados*, avaliação contra evidência auditada, **revisão independente obrigatória** (bloqueia auto-revisão por identidade normalizada), rejeição de repetição por *fingerprint* de observação, e máquina de estados que só deixa `RESOLVIDO` com resultado real + revisão aceita.
- **`verification/artifacts.py`**: revalida cópia primária e secundária e casa o digest do resultado com a aquisição auditada antes de aceitar como evidência de experimento.
- **`agents`/`orchestrator`**: `doctor` (diagnóstico), `CodexAdapter` (subprocesso limitado, sem shell, sem interpolação), `ClaudeAdapter` (stub que falha explicitamente — declarado pendente).

---

## 3. Pontos fortes (o que está bom)

1. **Honestidade técnica [FATO].** Docs e código separam consistentemente "assinatura reconhecida" de "formato validado", "alta entropia" de "criptografia provada", "triagem" de "dados recuperados". `platform_complete` é literalmente `false` no fim da demo. Raro e valioso.
2. **Postura de segurança do próprio sistema [FATO].** Evidência nunca é executada; conteúdo de evidência nunca vai para agente (só campos derivados em allowlist: `size`, `entropy`, `format`, `copy_verified`); prompt do agente declara todo valor como dado não confiável; chaves/plaintext nunca entram na auditoria (só um `material_id` opaco); limites de bytes/tempo/tentativas em toda operação cara.
3. **Rigor científico codificado [FATO].** A impossibilidade de auto-revisão, a exigência de revisão para finalizar e a invalidação de snapshot quando a investigação muda durante a verificação são garantias reais, testadas.
4. **Concorrência levada a sério [FATO].** `BEGIN IMMEDIATE` antes de ler a cadeia de auditoria, verificação de *lease*/token antes de gravar resultado, `busy_timeout` e `foreign_keys=ON`. Há teste dedicado de concorrência de auditoria.
5. **Migrações aditivas [FATO].** Esquema evoluiu 1→3 sem destruir dados; a própria `docs/validation.md` relata teste de migração preservando hashes e auditoria.

---

## 4. Inconsistências e riscos (achados da revisão)

Nenhum destes é bloqueante nem exige reescrita; são itens para o Codex decidir. Não editei código central para não colidir com o trabalho dele.

1. **O documento de escopo autoritativo não está no repositório [FATO].** A tarefa referencia "a seção 14 do escopo", mas o repo só contém docs de planejamento derivados pelo Codex (`implementation-plan`, `continuation-plan`, `roadmap`). **Consequência:** esta revisão compara código vs. planos do Codex, **não** vs. o escopo original. *Proposta:* versionar em `docs/` uma cópia (redigida, sem nada confidencial) do escopo, para que toda revisão futura tenha uma linha de base autoritativa. **[risco: médio — processual, não de código]**
2. **`config/default.toml` não é lido pelo código [FATO].** O arquivo declara `max_bytes`, `timeout_seconds`, `max_attempts`, `agent_calls_per_case`, mas os valores de runtime vêm de ambiente/flags; os limites `3` (tentativas, recuperação) e `5` (chamadas de agente em `orchestrator.review_summary`) são **constantes no código**, não lidas do TOML. O próprio arquivo diz ser "public reference", então é intencional — mas um leitor pode supor que editar o TOML muda o comportamento. *Proposta:* ou carregar o TOML, ou renomeá-lo/comentar para deixar claro que é só documentação. **[risco: baixo — confusão operacional]**
3. **Dois modelos de hipótese coexistem [INFERÊNCIA].** `run_one` insere automaticamente uma linha na tabela legada `hypotheses` (schema 1) a partir da entropia, enquanto o ciclo científico usa `hypothesis_records`/`hypothesis_history` (schema ≥2). Funciona, mas há duas "hipóteses" com semânticas diferentes. *Proposta:* documentar explicitamente a distinção (hipótese automática/heurística vs. hipótese científica manual) ou unificar. **[risco: baixo — clareza]**
4. **CI valida só Windows [FATO].** O workflow roda apenas em `windows-2022`. O código roda em Linux (comprovado nesta sessão). Não é defeito, mas uma matriz Linux no CI pegaria regressões de portabilidade de graça. *Proposta:* avaliar adicionar um job Linux (não bloqueante) à matriz. **[risco: baixo]**
5. **Deriva de contagem de testes na documentação [FATO].** `docs/roadmap.md` ainda cita "33 testes" na linha da Fase 1; `docs/validation.md` acumula 33 → 50 → 94. A realidade atual é 94. *Proposta:* eleger `docs/validation.md` (último checkpoint) como fonte única e referenciar a partir dos outros docs. **[risco: baixo — documentação]**
6. **`local_path` rejeita qualquer `:` no caminho [INFERÊNCIA].** Correto e desejável no alvo Windows (bloqueia ADS/device). Em POSIX, `:` é caractere legal de nome de arquivo, então um arquivo legítimo com `:` no nome seria recusado. Irrelevante para o alvo Windows; registrar apenas caso se decida suportar Linux como alvo de primeira classe. **[risco: muito baixo]**

### Riscos de segurança do próprio sistema — já reconhecidos (confirmo honestidade)

Estes **já estão documentados** em `docs/security.md`; confirmo por leitura do código que a documentação é fiel **[FATO]**, e registro para visibilidade da seção de segurança:

- **Auditoria é à prova de adulteração *detectável*, não *imutável*.** Quem tiver escrita no SQLite pode recomputar toda a cadeia. Não é assinatura digital nem cadeia de custódia forense. → Mitigação real exige retenção externa assinada.
- **Sem zeroização de memória** de chave/plaintext; sem proteção contra administrador local do processo Python.
- **TOCTOU de evidência:** `fstat` antes/depois reduz, mas não elimina, troca por processo privilegiado concorrente. → Para perícia real, mídia protegida contra escrita.
- **SQLite não cifra nem tem ACL por linha;** confidencialidade depende de NTFS/BitLocker operacionais, declarados como responsabilidade externa.
- **Integração real com agentes não validada no runner atual:** Codex teve login comprovado só em ambiente local específico; Claude está ausente por design. Nomes de revisores são declarações locais, não identidades autenticadas.

Nenhum destes é uma falha escondida — são limites honestos. O risco seria **apresentá-los a um cliente como se não existissem**, o que a documentação explicitamente evita.

---

## 5. Lacunas entre escopo (planejado) e código (entregue)

Com a ressalva do item 4.1 (escopo autoritativo ausente), comparando com os docs de planejamento do Codex, continuam **declaradamente pendentes [FATO]** — e isso está correto, não é omissão:

- Worker persistente / tarefa gerenciada Windows / boot; cancelamento cooperativo completo; worktrees Git por tarefa e locks por arquivo.
- Revisão cruzada automatizada entre agentes; autenticação real de revisores.
- Parsers íntegros por família (hoje: limitados/cabeçalho); perícia avançada; adaptadores de ferramentas profissionais externas.
- Pesquisa web automática, busca de vulnerabilidades, extração de chaves, varredura de rede, gravação automotiva — **ausentes por design** nesta fase.
- Tetos financeiros/recursos rígidos (Job Objects), monitoramento.
- Validação com hardware real e matriz integral de integrações.

---

## 6. Proposta de divisão de trabalho (Codex × Claude)

Alinhada ao papel que o próprio escopo reserva a cada agente.

**Codex — engenharia principal (constrói):**
- Implementação dos módulos das Fases 2–6 e integração em `service.py`/CLI/SQLite/relatórios (ponto único, para evitar edição simultânea — como o próprio `continuation-plan.md` já estabelece).
- Novos parsers, adaptadores de ferramentas, worker persistente, migrações de esquema.
- É o dono dos caminhos centrais; mudanças grandes ali são dele.

**Claude — revisão independente e investigação (verifica e questiona):**
- Revisão de cada PR do Codex: reproduzir testes, ler o diff de forma adversarial, checar limites/segurança, confirmar que a documentação não exagera o que o código faz.
- Atuar como **revisor independente declarado** no ciclo científico quando houver separação real de identidade (o sistema já proíbe auto-revisão — Claude pode ocupar esse papel legitimamente).
- Investigação técnica pontual e provas de conceito **em branches `claude/` + PR**, nunca sobrescrevendo arquivos centrais em desenvolvimento; quando precisar mexer em algo central, descrever a proposta no PR.
- Manter esta pasta `docs/review/` como histórico de revisões datadas.

**Regras de convivência confirmadas:** nada de commit direto em `main`/`master`; branches `claude/` + PR; sem enviar dados confidenciais/credenciais/evidências para fora; não editar o que o Codex está claramente desenvolvendo ao mesmo tempo.

---

## 7. Veredito e próximo passo sugerido

**[FATO]** Há uma base substancial, real e honesta — não é esqueleto. 94 testes passam, a demo roda, a documentação é fiel ao código e a postura de segurança é consistente. A "plataforma completa" **não** está entregue, e o próprio sistema diz isso.

**Próximo passo que proponho** (para o Codex decidir): resolver primeiro os itens processuais baratos — versionar o escopo autoritativo em `docs/` (4.1) e unificar a fonte de contagem de testes (4.5) — e decidir sobre `config/default.toml` (4.2). São rápidos e destravam revisões futuras com uma linha de base clara. A engenharia pesada (Fases 2–6) segue com o Codex; eu acompanho cada PR na revisão.

Bloqueios encontrados nesta sessão: **nenhum** para a tarefa de revisão. A única limitação registrada é a ausência do documento de escopo autoritativo no repositório (item 4.1), que não contornei — apenas registrei.

---

## 8. Acompanhamento — ajustes aplicados (a pedido do proprietário)

Em seguida à revisão, o proprietário autorizou aplicar parte dos achados. Feito nesta mesma branch/PR, com a suíte passando (**98 testes OK** isoladamente — 94 anteriores + 4 novos de configuração; **118 OK** após mesclar a `main` com a orquestração beta do Codex) e demo com exit 0:

- **Item 4.2 (config não era lido) — resolvido.** Novo `cyber_core/config.py` carrega `config/default.toml` (ou o arquivo apontado por `CYBER_CONFIG`) de verdade; precedência CLI > variável de ambiente > arquivo > embutido. A pedido do proprietário, **o limite de tempo deixou de ser um prazo operacional**: o teto virou apenas uma barreira de sanidade (365 dias), então uma tarefa autorizada pode rodar por horas ou dias. Novas flags `--max-attempts` e `--agent-calls-per-case`; `max_attempts` e `agent_calls_per_case` agora vêm da configuração em vez de constantes no código (o teto de tentativas de recuperação em `cryptanalysis` segue fixo em 3 por ser salvaguarda distinta).
- **Item 4.3 (dupla hipótese) — unificado.** "Hipótese" passa a ter **um único sentido**: os registros científicos (`hypothesis_records`). A heurística automática de entropia deixou de ser gravada como "hipótese" e virou uma **nota de análise** (`analysis_notes`, esquema SQLite 4, migração aditiva). Os portões de integridade científica (revisão independente, finalização) **não foram tocados**; a tabela legada `hypotheses` de bancos antigos é preservada e apenas não é mais escrita nem reportada.
- **Item 4.4 (CI só Windows) — resolvido.** O workflow agora roda em matriz **Windows + Linux** (Windows segue como alvo oficial).
- **Item 4.5 (contagem de testes) — resolvido.** `docs/validation.md` é a fonte única; `docs/roadmap.md` deixou de citar um número fixo e passou a referenciá-la.

**Pendente — item 4.1 (documento de escopo autoritativo).** Não foi aplicado porque o conteúdo do escopo **não está disponível no repositório** e não cabe inventá-lo. Depende de o proprietário fornecer o texto (versão redigida, sem nada confidencial) para ser versionado em `docs/`.
