# Revisão do projeto e pendências — 17/10/2026

## Resultado e limites

**O projeto tem um núcleo beta funcional, mas a plataforma profissional das 21 seções ainda não está completa.** Há código e testes reais para investigação de arquivos, persistência, autorização por escopo, fila, cancelamento, supervisão de processos e ciclo científico. A quantidade de testes não representa uma porcentagem de conclusão.

Esta revisão cruza o inventário completo de arquivos, implementações relevantes, testes, documentação e recibos do GitHub Actions com o [escopo original versionado pelo Claude](https://github.com/oscaveras-a11y/JarvisEspecialista/blob/70deac283947e2245af59e2a8709c5e525d3f7de/docs/escopo.md). É uma avaliação de cobertura e integração com sondas sintéticas específicas, não uma certificação de segurança ou perícia, nem prova de ausência de outros defeitos.

As instruções atuais do proprietário prevalecem sobre o plano inicial: **somente GitHub; nenhuma instalação ou execução do produto no seu computador; teste pessoal sem login da aplicação; somente ele usa e administra o beta.** Codex e Claude continuam desenvolvendo e testando. Login está adiado por decisão expressa e não é bloqueio para esses testes pessoais.

### Versões examinadas

| Conjunto | Referência imutável | Situação |
|---|---|---|
| Principal | `c43e4854f7a6a61826ab6309db5b87cd8ac8c4ca` | Main após o [PR #8](https://github.com/oscaveras-a11y/JarvisEspecialista/pull/8): teste pessoal sem login. 81 arquivos, 31 fontes Python no pacote, 14 arquivos de testes, 161 testes descobertos. |
| Trabalho Claude | `70deac283947e2245af59e2a8709c5e525d3f7de` | [PR #3](https://github.com/oscaveras-a11y/JarvisEspecialista/pull/3) aberto na consulta; 121 arquivos, 227 testes descobertos. Não integrado por esta revisão. |
| Diagnósticos desta revisão | `8b598d6d7abd0f8dd294f753735d9c36a4132eff` | [PR #9](https://github.com/oscaveras-a11y/JarvisEspecialista/pull/9), derivado da main acima; combina o candidato fixo apenas no runner temporário. Nenhuma mudança no código do produto. |

O repositório foi renomeado de CyberCore para **JarvisEspecialista**, preservando o repository ID `1415716753`. O pacote/CLI ainda usam `cyber-core`/`cyber`; não foi solicitado renomear essas interfaces.

## O que está comprovado

- Investigação com objetivo, responsável declarado, escopo, justificativa, validade, revogação e permissão específica de recuperação.
- SQLite, checkpoints, retomada de leases, concorrência, auditoria encadeada e preservação de resultados já confirmados.
- Worker limitado por tempo/tarefas, pausa/retomada e cancelamento persistente, inclusive descarte de resultado tardio.
- Aquisição de cópia verificada, SHA-256, tamanho, entropia e assinaturas; análise estática sem executar o arquivo examinado.
- BIN, Intel HEX, Motorola S-record, cabeçalhos ELF/PE e comparação limitada de firmware; análise/comparação de logs CAN clássicos.
- Triagem de recuperação por arquivo/lote. Recuperação AES-GCM real, restrita ao envelope sintético CCAES1 com chave fornecida.
- Hipóteses versionadas, critérios falsificáveis, avaliações, revisões declaradas, estratégias priorizadas, alternativas condicionadas e relatórios.

O item 4 está entregue **no contrato operacional beta documentado**, com 29 testes próprios. Sua ambição integral continua parcial: hipóteses, fontes e alternativas são fornecidas pelo operador/agente; o ranking é heurístico e não uma probabilidade científica calibrada. Não existe um investigador autônomo geral que pesquise e descubra soluções por conta própria.

### Recibos de testes

| Evidência | Resultado lido nos logs |
|---|---|
| [PR #8, run 39036388279](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39036388279) | Windows/Python 3.12: 161 testes executados, OK em 62,058 s; dependências, compilação, CLI e demo aprovadas. |
| [Candidato Claude, run 39035800054](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39035800054) | Windows: 227 executados, OK em 110,233 s. Linux: 227 descobertos, 225 executados e 2 skips específicos de Windows, OK em 19,886 s. |
| [Contratos do candidato, run 39035800031](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39035800031) | Suíte, 3 sondas de prazo/tentativas, demo e passagem item 4 → memória item 5 aprovadas nos dois sistemas; esquema global 7 preservado. O merge do candidato antigo foi “Already up to date”, pois já era ancestral. |
| [Reprodução independente desta revisão, run 39036837456](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39036837456) | Combinação da main examinada com Claude 70deac… apenas no runner. Linux: 227 descobertos, 225 executados, 2 skips, OK em 19,894 s; 3 sondas e handoff aprovados. As cinco observações abaixo foram reproduzidas. |

O workflow de diagnóstico termina com sucesso quando consegue executar as sondas. Seu JSON declara `release_approval: false`: **um check verde não transforma os problemas observados em comportamento aprovado**. Não houve chamada real aos provedores, varredura de rede, dispositivo, dado de cliente ou segredo real. A integração Codex real citada em `docs/validation.md` é histórica; os runners atuais não a repetem. O adaptador Claude do produto ainda recusa execução por falta de validação.

## Correções necessárias no candidato antes de integrá-lo

Os cinco achados abaixo pertencem ao candidato Claude fixado, não a funcionalidades já presentes na main examinada. Não foram corrigidos nesta revisão. O [diagnóstico reproduzível](../scripts/check-project-status.py) usa somente entradas inventadas.

| ID / prioridade | Evidência → achado | Efeito e critério de correção |
|---|---|---|
| F1 / alta | [vulnerability, linhas 28 e 45](https://github.com/oscaveras-a11y/JarvisEspecialista/blob/70deac283947e2245af59e2a8709c5e525d3f7de/src/cyber_core/vulnerability/__init__.py#L28): em uma linha com senha e DEBUG, a redação protege o achado de senha, mas o achado de DEBUG devolve a linha com a senha inteira. Sonda: `secret_visible_in_another_finding_excerpt=true`. | Um valor confidencial pode aparecer na resposta/saída da CLI. A auditoria SQLite testada guarda contagens, não esse segredo; não foi demonstrado vazamento real. Redigir todos os valores sensíveis antes de gerar qualquer trecho e testar combinações de regras, múltiplos segredos e chaves. |
| F2 / média | [Core.audit_config](https://github.com/oscaveras-a11y/JarvisEspecialista/blob/70deac283947e2245af59e2a8709c5e525d3f7de/src/cyber_core/service.py#L540) revalida autorização, mas não pausa. A sonda pausa um caso e inicia outra análise com êxito: `new_config_analysis_executes_while_paused=true`. | Os comandos novos não seguem integralmente o controle operacional da fila. Aplicar um guard comum e testar pausa, cancelamento, revogação e retomada em todas as rotas de análise, incluindo autoteste e captura. |
| F3 / média | A mesma análise retorna 1 achado, mas deixa `config_analysis_persisted_tasks=0` e `config_analysis_persisted_results=0`. A fonte mostra retorno direto e auditoria apenas de contagens. | Não é possível reconstruir os achados completos pelo histórico normal de resultados/relatório. Integrar as novas análises a aquisição verificável, tarefas, resultados, relatórios e revisão, com tratamento explícito de conteúdo sensível. Não basta gravar texto bruto com possíveis segredos. |
| F4 / média | [Core.analyze_capture](https://github.com/oscaveras-a11y/JarvisEspecialista/blob/70deac283947e2245af59e2a8709c5e525d3f7de/src/cyber_core/service.py#L514): arquivo de 2 mensagens, amostra de 3 bytes → 1 mensagem e `capture_truncation_reported=false`. O código lê todo o arquivo antes de recortar. | Uma análise parcial pode parecer completa; o limite de amostra não limita a leitura inicial. Ler somente o teto + indicador de continuação, declarar truncamento nas duas entradas e tratar registro cortado. Rever também a sinalização dos tetos de IDs/payloads distintos. |
| F5 / média | [research._matches](https://github.com/oscaveras-a11y/JarvisEspecialista/blob/70deac283947e2245af59e2a8709c5e525d3f7de/src/cyber_core/research/__init__.py#L20) usa sufixo textual sem fronteira de domínio. Uma URL sintética com hostname `unrelated-ietf.org` é rotulada `official`. Nenhuma conexão foi feita. | A autoridade da fonte pode ser superestimada. Para domínios completos, exigir igualdade ou subdomínio delimitado por ponto; tratar sufixos de categoria separadamente e testar domínios semelhantes. O rótulo continua heurístico, mesmo após corrigido. |

A inspeção também mostra que strings, diferenciação, captura e auditoria de configuração entram por métodos diretos do processo principal, fora da allowlist de quatro operações do filho supervisionado. É uma lacuna de integração a fechar com os itens 12/14, não prova de que essas rotas estejam cobertas pelo isolamento já entregue. As sondas acima não constituem uma auditoria exaustiva de todas essas rotas.

## Cobertura das 21 seções

**Legenda:** “beta” significa comportamento delimitado com evidência; “parcial” significa requisitos restantes; “candidato” exige integração revisada. Codex mantém as seções pares e Claude as ímpares. Achados em código compartilhado exigem coordenação de contratos; esta revisão não muda essa divisão.

| Seção / responsável | Estado observado e evidência | O que falta para o escopo integral |
|---|---|---|
| 1 — Missão / Claude | Parcial. Objetivos e limites documentados; demo admite plataforma incompleta. | Investigações profissionais reproduzíveis com módulos especializados e dois agentes efetivamente integrados; validação além de controles sintéticos. |
| 2 — Ambiente / Codex | Adaptado à ordem atual: GitHub-only, Python/SQLite e runners temporários. TOML é só arquivo na main; carregamento real está em `config.py` do candidato. | Integrar a configuração validada e definir o ambiente do beta compatível com GitHub-only. Não há comprovação do orçamento original de 8 GB por execução real nesse limite; o runner não equivale ao PC especificado. |
| 3 — CORE e agentes / Claude | Parcial. Main possui fila e revisão Codex por resumo; candidato acrescenta classificação, plano, decomposição e atribuição ao CORE. | Broker real entre agentes, execução/revisão cruzada, tratamento e retomada de falhas de provedor; ClaudeAdapter continua bloqueado. Plano determinístico não é planejamento investigativo completo. |
| 4 — Raciocínio / Codex | Beta operacional entregue em `investigation/reasoning.py`; registros, ranking, alternativas, bloqueios, avaliação e relatório. | Produção assistida de hipóteses/alternativas, pesquisa integrada, qualidade/calibração e casos difíceis; entradas continuam declaradas e revisão exige intervenção. Não chamar a seção inteira de investigação autônoma concluída. |
| 5 — Memória / Claude | Beta na main: SQLite, evidências, histórico científico, auditoria e checkpoints. Candidato acrescenta recall por hash/tipo, planos e notas de análise. | Integrar candidato, fechar F3, comprovar backup/restauração e recuperação durável fora de um único job; melhorar consultas/indexação conforme volume. |
| 6 — Engenharia reversa / Codex | Parcial. `firmware` valida estruturas limitadas e compara; assinaturas/entropia na main, strings no candidato. | Ghidra/Capstone/Binwalk/equivalentes realmente integrados e testados; desmontagem, decompilação, estruturas/regiões de memória e formatos proprietários/ofuscados. Cabeçalho ELF/PE não cobre análise completa de EXE/DLL. |
| 7 — Criptografia / Claude | Parcial. Triagem e AES-GCM CCAES1 com chave na main; candidato acrescenta diferenciação e autoteste CCPW1 com lista de senhas próprias. | Reparar arquivos danificados, parsers/validação por família, auditoria de implementações, ferramentas autorizadas para contêineres reais. Não há recuperação universal de ZIP/PDF, nem demonstração completa de RSA/ECC/ChaCha20. CCPW1 é laboratório. |
| 8 — Perícia / Codex | Parcial. Cópias verificadas, hashes e auditoria; linha do tempo derivada no candidato. | Imagens de disco, sistemas de arquivos, recuperação de dados, metadados específicos, Autopsy/TSK/YARA e relatório pericial estruturado. Cadeia SHA-256 não é assinatura ou custódia imutável. |
| 9 — Vulnerabilidades / Claude | Ausente como módulo na main; candidato oferece regras estáticas em configuração. | Corrigir F1/F3; integrar e testar Semgrep/ZAP/Nmap/YARA/auditoria de dependências conforme escopo; fluxos de Windows/Linux/web/API/rede/firmware. Regex é indício, não validação de vulnerabilidade. |
| 10 — Protocolos / Codex | Parcial. CAN clássico offline na main; candidato soma captura textual hex genérica. | Corrigir F4 e integrar ao fluxo; CAN FD, DBC/decodificação, PCAP/TCP/IP/HTTP e formatos USB/UART/SPI/I2C, reconstrução de estruturas/máquinas de estado e adaptadores. Parsers offline podem avançar antes de hardware; ensaios físicos dependem de equipamento. |
| 11 — Pesquisa / Claude | Parcial. Fontes inseridas manualmente; candidato classifica domínio offline. | Corrigir F5; busca autorizada, coleta/versionamento, preservação e confronto de documentação, artigos, CVEs e manuais. Registrar URL não comprova consulta ou confiabilidade. |
| 12 — Execução prolongada / Codex | Beta. Fila, leases, checkpoints, limites de tentativa/tempo, worker sequencial e cancelamento. | RAM/CPU rígidos, orçamento financeiro/tokens aplicado, agendamento/reinício automático e recuperação de conexão/provedor; durabilidade entre ambientes. Worker aceita no máximo 24 h por invocação; jobs atuais têm teto de 20 min. Não foi provada uma investigação autônoma de vários dias. |
| 13 — Verificação / Claude | Beta. Evidência revalidada, critérios e revisão por nome declarado; main aceita 4 estados em `finalize`, candidato aceita 6. | Unificar os estados: “falha de execução” existe na tarefa, não como estado de investigação aceito por `finalize`. Revisão efetiva entre agentes e validação profissional ainda faltam; nomes distintos não comprovam identidades distintas. Login do beta continua adiado. |
| 14 — Segurança do sistema / Codex | Parcial. Escopo, revogação, auditoria, separação de dados e encerramento da árvore de processos nas quatro análises monitoradas. | Fechar F1/F2/F3 nas rotas novas; limites de privilégios/rede/CPU/RAM e gestão de segredos. Job Object controla ciclo de vida, não constitui sandbox de privilégios/rede. Limpeza de cópias órfãs e proteção integral contra troca concorrente de arquivos permanecem limitadas. |
| 15 — Interface / Claude | CLI beta; candidato acrescenta logs, recall, planejamento e comandos novos. | Roteiro de teste pessoal simples no GitHub com cenários sintéticos e saídas claras. Não há painel operacional hospedado. GUI profissional é fase futura, posterior à validação do núcleo, e não requisito para o teste pessoal atual. |
| 16 — Estrutura / Codex | Atendida para a estrutura implementada: `src/cyber_core`, scripts, testes, docs e configuração, com dados operacionais fora do Git. | Manter organização e documentação conforme os módulos crescem. A diferença deliberada para a árvore ilustrativa original não exige pastas vazias nem reestruturação só por aparência. |
| 17 — GitHub / Claude | Branches, PRs, CI com permissões de leitura e histórico presentes. Repositório privado, mesmo ID após renomeação. | Integração controlada do PR #3 após correções, coordenação/worktrees isolados para tarefas dos agentes e prova das proteções de branch. Consulta de proteção foi negada ao conector; rulesets retornaram restrição do plano. Isso não permite afirmar que proteções estão configuradas ou ausentes. |
| 18 — Testes / Codex | 161 testes na main e 227 descobertos no candidato; testes negativos, concorrência e retomada, além das sondas desta revisão. | Regressões dos cinco achados e matriz de todos os módulos/rotas, integrações reais de agentes/ferramentas, limites de recursos, execuções prolongadas e hardware. Dois skips no Linux são casos específicos de Windows, não dois testes executados. |
| 19 — Fases / Claude | Há planos e entregas incrementais, mas `docs/roadmap.md` usa 6 agrupamentos diferentes das 9 fases originais. | Alinhar o painel de progresso às nove fases abaixo, com critérios e evidências; não usar contagem de arquivos ou testes como conclusão de fase. |
| 20 — Entrega / Codex | Código, CI e registros de beta existem; não há release publicada na consulta à API. | Consolidar documentação atual, dependências/versionamento e pacote de entrega validado por fase, registrando bloqueios reais. Não basta criar arquivos ou aprovar a suíte existente. |
| 21 — Responsabilidades / Claude | Processo incremental e divisão documentados em `AGENTS.md` e `project-ownership.md`. | Manter comunicação honesta, trabalhar na seção atribuída e avaliar a combinação exata; o objetivo profissional final ainda não foi atingido. |

## Ordem recomendada de trabalho

1. **Fechar F1–F5 e cobrir regressões antes de integrar o candidato Claude.** Primeiro redação de segredos; depois uniformizar execução, pausa, aquisição e persistência dos novos módulos. Revisar a combinação exata sem modificar automaticamente a branch do outro agente.
2. **Preparar o teste pessoal no GitHub, sem login adicional.** Cenários sintéticos selecionáveis, resultado esperado, resumo legível de sucesso/falha e relatório seguro. O workflow manual atual executa a suíte/demo fixa; não é um ambiente de investigação interativo ou armazenamento operacional permanente.
3. **Consolidar os contratos do núcleo e da memória.** Configuração única, esquema/migrações, estados, novas análises na fila/relatório, backup/restauração e semântica de pausa/cancelamento em todas as rotas.
4. **Continuar os pares na ordem: item 6, depois 8, 10, 12, 14, 16, 18 e 20.** Cada incremento deve ter critério de aceite observável e ferramenta realmente executada no GitHub quando aplicável. Claude mantém os ímpares; não transferir silenciosamente suas pendências ao Codex.
5. **Validar agentes e módulos profissionais conforme as dependências existirem.** Não instalar no computador do proprietário. Quando credencial, ferramenta, hardware ou limite de serviço for necessário, registrar a dependência concreta; não simular integração.
6. **Atualizar os documentos de estado e fechar uma entrega beta delimitada.** GUI e autenticação futura seguem a prioridade do proprietário; não bloqueiam o teste pessoal atual.

### Correspondência com as nove fases originais

| Fase original | Situação desta revisão |
|---|---|
| 1 — Fundação | Base beta entregue; configuração TOML e migrações novas ainda no candidato. |
| 2 — Orquestração | Parcial: fila/worker existem; segundo agente, broker e autonomia prolongada faltam. |
| 3 — Investigação de arquivos | Beta delimitada; formatos e metadados ainda incompletos. |
| 4 — Engenharia reversa e criptografia | Parcial: parsers/triagem/envelopes sintéticos; ferramentas profissionais e recuperação por formato faltam. |
| 5 — Forense e protocolos | Parcial: preservação/CAN; disco, demais protocolos e ferramentas faltam. |
| 6 — Segurança e vulnerabilidades | Inicial; candidato estático tem correções pendentes. |
| 7 — Claude Code | Adaptador do produto não validado; colaboração de desenvolvimento não equivale a integração do agente no produto. |
| 8 — Validação completa | Em andamento; não concluída por testes do protótipo. |
| 9 — Interface gráfica | Adiada até validar o núcleo, conforme o escopo. |

## Inconsistências documentais a corrigir

- README e roadmap ainda dizem que isolamento de análise está pendente, embora as quatro operações monitoradas já estejam implementadas; a fronteira correta é ciclo de vida de processos, sem sandbox de privilégios/rede.
- O roadmap cita 33/114 testes e seis fases antigas; `docs/validation.md` é histórico, não recibo único da versão atual. Preservar o histórico e apontar para um status datado/imutável.
- O documento do item 4 usa “concluído” para o contrato operacional; isso não deve ser apresentado como cobertura integral da investigação autônoma.
- A verificação Claude dos itens 6–21 afirma que todos os estados estão cobertos; o código ainda não aceita “falha de execução” como estado de investigação. O mesmo documento atribui por engano o item 17 ao Codex, embora seja ímpar.
- O README do candidato ainda traz a exigência anterior de autenticação; a main e AGENTS atuais, após PR #8, permitem teste pessoal sem login. A combinação deve preservar essa ordem atual.
- Há links com o nome antigo do repositório e descrições históricas. Não confundir redirecionamento/nome do repositório com renomeação do pacote ou entrega de funcionalidade.

Esta revisão entrega um inventário de pendências e reproduções. **Não aprova automaticamente o PR #3, não corrige os cinco problemas e não declara a plataforma completa.**
