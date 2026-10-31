# Recuperação assistida por IA (Qwen3) — plano para implementar nesta semana

Decidido com o proprietário em conversa (2026-10-30). Escopo do item 7
(criptografia/recuperação), Claude. Objetivo: registrar o desenho exato
combinado para não se perder entre sessões, e deixar claro o que pode ser
construído agora (sem depender do Qwen3 já estar rodando) e o que só entra
quando isso rodar no computador do proprietário.

## Decisão de arquitetura (fechada, não renegociar sem o proprietário)

A IA **nunca** testa, nunca confirma e nunca "acha" uma senha. Ela só
**gera candidatas**. Quem testa e confirma é sempre a ferramenta real
(hashcat / John the Ripper reais, já implementados pelo Codex em
`cryptanalysis/sessions.py` + `external_tools.py`, ou os verificadores
nativos de ZIP/PDF/7z/RAR5). Esse limite é o pilar do projeto (nunca
apresentar não-verificado como verificado) e não é negociável.

## Pipeline em duas camadas

1. **Camada 1 — banco conhecido (já existe hoje).** A lista rockyou
   embutida (`cryptanalysis/wordlists.py`, 14.344.391 senhas reais
   vazadas) materializada como arquivo real via
   `Core.materialize_wordlist()` / `cyber materialize-wordlist`, testada
   pelo `recovery-session` do Codex (hashcat/John reais). Sem IA
   nenhuma nesta camada.

2. **Camada 2 — IA como fallback, só se a camada 1 esgotar sem achar.**
   - O Qwen3 recebe as pistas que o proprietário fornecer (nomes, datas,
     apelidos, referências, texto livre) **uma única vez** — ele não gera
     senha por senha em tempo real (velocidade: um teste de hashcat roda
     ordens de magnitude mais rápido que uma geração de IA token a
     token; a IA seria o gargalo, não a ferramenta).
   - A saída do Qwen3 é um conjunto de **temas/palavras-base** (não a
     lista final de tentativas).
   - Um **gerador local de variações, baseado em regras** (sem IA, rápido,
     pode rodar por horas/dias sem custo de inferência) expande cada
     tema em milhares/milhões de variações realistas (maiúscula/
     minúscula, números, símbolos, anos, separadores comuns — leetspeak).
   - Essa lista expandida entra no **mesmo** `recovery-session` real da
     camada 1 (mesmo contrato, mesmo `--candidates`, mesmo
     hashcat/John/verificadores nativos). Nenhuma mudança no sistema de
     teste/confirmação do Codex é necessária.
   - Pode rodar por tempo longo (o proprietário mencionou até ~2 dias)
     até esgotar ou achar — isso já é possível hoje no `recovery-session`
     via sessões retomáveis/checkpoint, sem precisar de nada novo nessa
     parte.

## O que pode ser construído AGORA (não depende do Qwen3 rodando)

- [x] **Gerador local de variações a partir de pistas** — feito em
      2026-10-30 (`cryptanalysis/wordlist_generator.py`): regras de case,
      leetspeak, números/anos (1950-2026), separadores comuns,
      combinações de 2+ palavras e sufixos numéricos+símbolo misturados
      (ex.: "Rex123!"). Determinístico, sem duplicatas. **Sem limite por
      padrão** (`limit=None`): roda indefinidamente — o sufixo numérico
      cresce em largura sem fim (2, 3, 4, ... dígitos) — até ser
      interrompido de fora (Ctrl+C, parar a `recovery-session`, ou o
      disco de destino enchendo). Um `--limit` explícito ainda pode ser
      passado para quem quiser um arquivo limitado. Exposto como
      `Core.materialize_generated_wordlist()` e o comando `cyber
      generate-wordlist <caso> <caminho> --word X --word Y [--limit N]`.
      As palavras-pista nunca entram na trilha de auditoria (mesmo
      tratamento dado a um segredo). Testado (unidade, serviço, CLI,
      ponta a ponta) — ver `tests/test_wordlist_generator.py`,
      `tests/test_wordlists.py`, `tests/test_cli.py`.
- [x] **Força bruta literal (exaustiva) sobre conjunto de caracteres** —
      feito em 2026-10-31, a pedido explícito do proprietário mesmo após
      eu explicar a impossibilidade matemática para comprimentos longos
      (`generate_bruteforce()` em `cryptanalysis/wordlist_generator.py`):
      enumera literalmente toda string de um charset (maiúsculas,
      minúsculas, dígitos e símbolos comuns por padrão — 89 caracteres),
      do comprimento mais curto para o mais longo. **Sem limite por
      padrão** (`min_length`/`max_length`/`limit` todos opcionais —
      `None` = sem fim), a pedido do proprietário ("tire o limite, deixe
      sem limite, deixa infinito, em vez de 1 milhão de linhas"): roda
      para sempre até ser interrompida de fora. Exposto como
      `Core.materialize_bruteforce_wordlist()` e o comando `cyber
      bruteforce-wordlist <caso> <caminho> [--charset ...]
      [--min-length N] [--max-length N] [--limit N]`. Testado (unidade,
      serviço, CLI) com bounds explícitos nos testes (para o próprio
      teste terminar) — ver as mesmas três suítes acima.
      **Explicação honesta mantida**: para o charset padrão, o número de
      strings de comprimento L é 89^L — em L=36 isso já passa de 10^70,
      mais átomos do que existem no universo observável (~10^80), então
      nenhuma quantidade de tempo rodando cobre isso de fato; o que a
      função agora faz sem limite é continuar tentando para sempre, não
      "terminar o impossível mais rápido". Para busca exaustiva REAL de
      senha curta, o modo mask-attack de uma ferramenta de quebra real
      (`hashcat -a 3`) é a ferramenta certa: ele enumera em código
      compilado direto contra o alvo, numa taxa que nenhum gerador em
      Python escrevendo um arquivo de candidatas alcança, e não precisa
      materializar arquivo nenhum. Exemplo de uso real (não implementado
      aqui — é um comando do hashcat em si, fora do escopo deste
      gerador): `hashcat -a 3 -m <modo> arquivo.hash ?a?a?a?a` tenta
      todas as combinações de 4 caracteres de qualquer tipo
      (`?a` = todo o conjunto maiúscula+minúscula+dígito+símbolo) direto
      contra o hash, sem nunca escrever uma lista de candidatas em disco.
- [x] **Reconciliação sessions.py/recovery_trial.py (achado #0) — feita em
      2026-10-31.** O Codex não respondeu à issue #35 em um dia; o
      proprietário pediu para eu mesmo resolver. Como esta branch nunca
      havia modificado `sessions.py`/`recovery_trial.py`/`operations.py`
      desde o commit-base comum (`47f1acc`) — só o `main` (PR #26,
      `de2fe89`) os estendeu com hashcat/John/formatos/RAR5 — a
      reconciliação foi trazer a versão do `main` (que é um superconjunto
      real, não um fork incompatível) para esta branch: `sessions.py`,
      `recovery_trial.py`, `cli/operations.py`, os módulos novos
      (`cryptanalysis/formats.py`, `cryptanalysis/rar5.py`,
      `external_tool_runtime.py`, `external_tools.py`,
      `external_tools_child.py`), os testes novos, os workflows de CI, a
      documentação (`recovery-multiformat.md` etc.) e o extra
      `recovery` do `pyproject.toml`. Mesclado manualmente só o ponto que
      ambos os lados tocaram (a lista de comandos despachados em
      `cli/__init__.py`), preservando os dois conjuntos. Validado: suíte
      completa (575 testes, 0 falhas; com as dependências reais
      instaladas — `pip install ".[recovery]"` — ainda menos testes
      pulados), `demo.py`, `try-me.py`, Playwright estático, e um teste
      de ponta a ponta manual real: criei um ZIP com senha de verdade
      (`pyzipper`, AES), rodei `cyber recovery-session start ... --mode
      zip` com a senha certa escondida entre candidatas erradas, e a
      sessão achou e validou de verdade (`password_validated: true`) na
      terceira tentativa. O item 1 da issue #35 (`_pdf` sem try/except)
      foi corrigido direto no `main` (commit `217f709`), antes desta
      reconciliação trazer o arquivo corrigido para aqui.
- [x] Lógica de "camada 2 só dispara se a camada 1 esgotar sem achar"
      (encadeamento entre duas sessões de `recovery-session`) — agora
      **desbloqueada** pela reconciliação acima: o `recovery-session`
      real (hashcat/John/formatos/RAR5) já existe nesta branch, e o
      gerador (camada 2) já produz arquivo de candidatas no formato
      certo que esse mesmo `recovery-session` consome sem mudança
      nenhuma. O encadeamento *automático* propriamente dito (disparar a
      camada 2 sozinho quando a camada 1 termina sem achar, sem o
      operador precisar rodar o segundo comando manualmente) ainda não
      foi escrito — ver próximo item.
- [x] Testes de geração determinística a partir de temas fixos (sem IA,
      só o gerador de regras) — feito.
- [ ] Teste de encadeamento camada 1 → camada 2 — pendente, junto com o
      item acima.

## O que só entra quando rodar no computador do proprietário (adiado)

- [ ] Conexão real com o Qwen3 (local, ex: via Ollama) para transformar
      pistas em texto livre → temas/palavras-base. Esse é o único passo
      que precisa do modelo de fato rodando; tudo antes dele pode ser
      testado com temas/palavras-base fornecidos manualmente (sintético).
- [ ] Decisão de empacotamento (qual runtime, requisitos de
      hardware/RAM, se via Ollama/vLLM/outro) — ainda não decidido com o
      proprietário além de "seria o Qwen3".

## Contexto da conversa que levou a este desenho

- Pergunta aberta: como ampliar a abrangência de cibersegurança do
  projeto. Discussão paralela (não aqui): varredura de dependências
  vulneráveis via base local do OSV — ver seção own do roadmap/escopo
  se for retomado depois.
- Proprietário propôs IA (Qwen3) para "ajudar as ferramentas em
  trabalhos maiores, onde as ferramentas têm limitações" — Codex/Claude
  ficam só na construção do projeto; o Qwen3 ficaria dentro do produto.
- Risco identificado e confirmado com o proprietário: IA não pode
  "confirmar" senha nem gerar senha-por-senha em tempo real (gargalo de
  velocidade) — por isso o desenho em duas camadas com gerador de regras
  no meio.
- Proprietário confirmou o desenho final e pediu para salvar e
  implementar ainda esta semana.
