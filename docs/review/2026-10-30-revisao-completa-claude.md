# Revisão completa de código — 2026-10-30

Pedido pelo proprietário: revisar todo o código e levantar bugs + lista de
melhorias. Revisão feita em 7 frentes paralelas cobrindo todo `src/` do
branch `claude/gifted-gates-kd07xv` e o código do Codex em `origin/main`
que ainda não está nesta branch. Nenhuma edição foi feita nesta revisão —
achados abaixo, para priorizar e corrigir separadamente.

## 0. Achado estrutural — precisa ser resolvido antes de qualquer merge

**`cryptanalysis/sessions.py` e `cryptanalysis/recovery_trial.py` existem
nos dois branches com conteúdo divergente, a partir da mesma base.**

Confirmado de forma independente por 4 das 7 revisões. Esses dois
arquivos já existiam nesta branch desde o commit `678a36c` (17/10,
"checkpointed recovery sessions and public pending-module flows"),
**antes** do merge-base `47f1acc`. O Codex, no `main` (commit `de2fe89`),
pegou essa mesma base e estendeu com integração a ferramentas externas
reais (hashcat, John the Ripper, formatos zip/7z/pdf/office/pkcs12/rar5
via `formats.py`/`external_tools.py`). Esta branch manteve a versão
original, que só cobre `ccaes1` e chave SSH.

- `sessions.py`: 93 linhas de diferença (de ~453/510 linhas totais).
- `recovery_trial.py`: 14 linhas de diferença (de ~65/73 linhas totais).
- O comando de CLI `recovery-session` e a classe `RecoverySessions`
  também divergem no mesmo sentido (confirmado pela revisão de
  cli/web_server.py).

**Isso não é duplicação de esforço (como já resolvemos antes com o
sistema de recuperação de senha simples) — é a mesma funcionalidade
evoluída em paralelo. Um merge direto vai conflitar linha a linha
nesses arquivos, e resolver "pegando um lado" perde funcionalidade real
de um dos dois.** Precisa de reconciliação manual: reaplicar a extensão
do Codex (hashcat/John/formatos) por cima da base, preservando os dois
lados.

## 1. Bugs confirmados (por ordem de gravidade)

### Segurança / vazamento de segredo

1. **`src/cyber_core/vulnerability/__init__.py:47-48` (`_mask`)** — a
   redação de segredos deixa os **2 primeiros caracteres visíveis**
   (`value[:2] + '***'`). Confirmado por execução: `password: abc` vira
   `password: ab***` no excerto devolvido — 2 de 3 caracteres do
   segredo real aparecem no resultado, contra a promessa do próprio
   módulo de nunca expor valor de segredo.

### Lógica / disponibilidade

2. **`src/cyber_core/cryptanalysis/__init__.py:35-39`** — o orçamento de
   3 tentativas vitalícias de recuperação (`recovery_attempts`) é
   incrementado **antes** de validar que o envelope existe, tem o magic
   `CCAES1` correto ou não está truncado. Um caminho errado ou arquivo
   malformado consome uma tentativa sem nunca testar a chave de
   verdade. Dois erros de operador por engano deixam só 1 tentativa
   real.

3. **`src/cyber_core/reverse_engineering/strings.py:46-61`
   (`_utf16le_runs`)** — a varredura de strings UTF-16LE só verifica
   offsets pares. Uma string UTF-16LE que comece num byte ímpar do
   buffer é completamente ignorada. Confirmado por execução direta
   (`extract_strings` não encontra uma string construída deliberadamente
   em offset ímpar). O teste existente só cobre o caso alinhado.

4. **`src/cyber_core/agents/runner.py:174`** — `process.wait(timeout=5)`
   no `finally` de `run_bounded()` não está protegido contra
   `subprocess.TimeoutExpired`. Se o processo não morrer em 5s após o
   `kill()`, a exceção escapa, mascara o erro real e pula o
   `join()`/fechamento dos streams que vêm depois. O código equivalente
   em `analysis_process/supervisor.py:122-126` já tem a proteção certa —
   mesmo padrão de "corrigido num lugar, não no outro" do bug do
   symlink (`_executable`, já corrigido no commit `1557b35`).

5. **`src/cyber_core/orchestrator/broker.py:149-158,220-227`** —
   `_stop()` levanta `CoreError` (em vez de devolver status) quando o
   lease já expirou. Isso escapa de `run_one()` sem tratamento na
   segunda chamada, pulando `_finish(...)`: o job fica em `running` com
   token morto até o próximo `claim()` reciclar como `uncertain`, em vez
   de finalizar limpo.

### No código do Codex (`origin/main`, ainda não nesta branch)

6. **`cryptanalysis/formats.py`, função `_pdf`** — é o único validador
   de formato sem `try/except` ao redor da biblioteca real (`pypdf`).
   Um PDF malformado/adversarial faz `_pdf` lançar excepção não tratada,
   que sobe até `recovery_trial.py` e vira um estado **terminal**
   (`resource_limited`) da sessão inteira — trava toda a tentativa de
   recuperação na primeira candidata, em vez de só pular para a próxima,
   como os outros formatos já fazem corretamente.

7. **`external_tool_runtime.py` + `reverse_engineering/_limit_exec.py`
   — `RLIMIT_CPU` soma tempo de CPU entre todas as threads, não tempo de
   relógio.** Com hashcat usando 2 threads a 100%, o limite de CPU é
   esgotado em ~metade do tempo de parede pretendido. Isso explica (e
   aprofunda) a investigação que já fizemos sobre a falha real do CI em
   `real_tools`/`real_rar5`.

## 2. Pontos de baixa confiança (não confirmados, vale olhar com mais contexto)

- `verification/artifacts.py:11` (`verify_copy`) — depende de
  `local_path()` resolver symlinks antes do `is_relative_to()`; não
  confirmado porque `local_path` está em outro arquivo fora do escopo
  dessa revisão específica.
- `investigation/reasoning.py:300` — `next(...)` sem valor padrão pode
  estourar `StopIteration` não tratado; parece inalcançável no fluxo
  normal, mas é frágil.
- `src/cyber_core/analysis_process/child.py` + `network_guard.py` — o
  bloqueio de rede só altera `socket.socket` depois que
  `reverse_engineering.analyze` já foi importado no topo do módulo; uma
  dependência futura que faça `from socket import socket` diretamente
  furaria o bloqueio sem nenhum teste pegando isso hoje.

## 3. Sugestões de melhoria (consolidadas, não são bugs)

1. Resolver a divergência de `sessions.py`/`recovery_trial.py` com o
   `main` antes de qualquer merge (crítico — ver seção 0).
2. Mover a checagem de `paused` para dentro de `_enqueue`/`enqueue` em
   `service.py`, em vez de depender de cada chamador verificar antes.
3. Corrigir a regex de `static_iv_or_nonce` em
   `cryptanalysis/implementation_audit.py:15` — a terceira alternativa
   do grupo está malformada e praticamente nunca casa com nada.
4. Renomear ou documentar melhor a diferença entre `inspect-disk/pcap` e
   `inventory-disk/pcap` (dois comandos de nome quase idêntico, fazendo
   coisas diferentes).
5. Fatorar o `--queue-only` duplicado em 4 subparsers do CLI.
6. `_pdf` em `formats.py` (Codex) precisa do mesmo `try/except` que os
   outros validadores já têm.
7. `_limit_exec.py` poderia escalar `RLIMIT_CPU` pelo número esperado de
   threads, em vez de 1:1 com o tempo de parede.

## Áreas revisadas sem bug confirmado

Núcleo (`service.py`, `memory`, `permissions`, `errors`, `config`,
`recovery.py`, `operations.py`), workflow científico/verificação
independente (`investigation/*`, `verification/*`, `reporting/*`,
`planning/*`, `protocol/*`, `research/*`), CLI e `web_server.py`/`web/*`,
firmware/forensics/pcap/automotive, YARA. Testados com atenção
específica aos riscos mais prováveis de cada área (adulteração de
evidência, path traversal, corrida de thread, vazamento de segredo) —
nada confirmado além do listado acima.
