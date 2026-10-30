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

- [ ] Gerador local de variações a partir de pistas (regras: case,
      leetspeak, números/anos, separadores, combinações de 2+ palavras).
      Entrada: lista de palavras/temas-base. Saída: arquivo de candidatas
      compatível com `recovery-session --candidates` (mesmos limites:
      até 100.000 linhas / 8 MiB por sessão, como a camada 1).
- [ ] Lógica de "camada 2 só dispara se a camada 1 esgotar sem achar"
      (encadeamento entre duas sessões de `recovery-session`, ou um
      comando novo que orquestra isso).
- [ ] Testes cobrindo: geração determinística a partir de temas fixos
      (sem IA, só o gerador de regras), encadeamento camada 1 → camada 2,
      e que nenhuma "senha" saia do gerador/IA sem passar pelo teste real.

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
