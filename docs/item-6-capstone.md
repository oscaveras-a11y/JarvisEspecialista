# Item 6 — leitura estática de instruções com Capstone

O fluxo `analyze-firmware` acrescenta `firmware.code_preview` aos resultados.
O CORE adquire e verifica a cópia, faz a análise no processo monitorado e
guarda a saída no SQLite/relatório. Nenhum binário examinado é executado.

## Seleção e significado

Para uma entrada ELF/PE com arquitetura declarada compatível, a prévia procura
os bytes em arquivo que correspondem ao ponto de entrada. ELF executável usa
PT_LOAD; segmentos NOTE e outros tipos não servem como mapa de carregamento.
Seções alocadas conflitantes, mapeamentos virtuais ambíguos e caudas zero-fill
são recusados. O fallback por seção permanece para objetos sem mapa LOAD
apropriado: objetos ET_REL usam uma seção individual, com índice e endereço
relativo explícitos, sem misturar seções distintas que começam em zero. Não
se inventa mapa de executável/dynamic sem LOAD. Outros tipos ELF não recebem
uma interpretação executável implícita.
Se não há entrada,
pode usar a primeira região declarada executável, identificando essa escolha
em `selection_basis`. Endereço virtual e offset de arquivo continuam distintos;
regiões sem bytes armazenados não são preenchidas nem decodificadas.

As arquiteturas deste incremento são x86, x86_64 e AArch64 little endian.
Outras arquiteturas/ordens recebem estado explícito de ausência de suporte.
AArch64 com entrada desalinhada não é arredondado silenciosamente. BIN/HEX/
S-record sem identificação de processador recebem `architecture_not_declared`;
não se escolhe uma CPU com base na extensão do arquivo ou em um palpite.

A saída traz endereço declarado, bytes hex, tamanho, mnemônico e operandos,
além de versão do backend e origem da seleção. Endereços vêm do cabeçalho,
sem aplicar relocação ou provar endereços reais de execução. Decodificar
bytes não demonstra alcance, intenção, segurança, função ou comportamento.

## Limites

- No máximo 4 KiB da região selecionada e 128 instruções.
- Mudanças de mapa/permissão ou limite da seção podem encurtar a prévia;
  nesse caso, mapping_truncated fica explícito.
- `sample_truncated`, `instruction_limit_reached`, `decoded_bytes` e
  `undecoded_bytes` deixam os limites e as interrupções da leitura explícitos.
- Não habilita skipdata, execução, emulação nem comandos derivados da amostra.
- Bytes inicialmente indecodificáveis retornam `no_instructions_decoded`,
  sem apresentar sucesso de leitura de instruções.
- Conserva os limites de bytes, prazo e encerramento de processos do CORE.
  Isso continua sendo supervisão de ciclo de vida, sem sandbox de privilégios.

A instalação padrão continua funcionando sem Capstone e informa
`dependency_unavailable` no resultado apropriado. O extra de pacote
`reverse` declara Capstone >=5.0.9 e <6; versões alpha não são escolhidas.
Nesta entrega, o extra é instalado **somente nos runners GitHub** para
validar a biblioteca real. Não há instalação no computador do proprietário,
chamada a provedor ou envio de evidências.

## Evidência e fronteira

Os primeiros testes foram publicados no PR #11 antes da implementação.
O run39038693126 instalou Capstone 5.0.9 no Linux e reproduziu seis falhas
de capacidades ausentes (três asserções e três campos ausentes; 246 testes
descobertos, com 2 skips específicos de Windows). Uma regressão adicional,
run39038905927, demonstrou que zero instruções era rotulado indevidamente
como decoded; a implementação passou a registrar ausência de decodificação.

A revisão independente encontrou escolha incorreta quando seção ELF e
PT_LOAD divergiam. O run39039274433 reproduziu quatro falhas: mapas divergentes,
seção sobre cauda zero-fill, segmento não LOAD tratado como mapa e sobreposição
virtual PE escolhida por ordem. A correção consulta LOAD e recusa ambiguidades
antes de invocar o backend. O run39039468540 também reproduziu colisão
indevida entre endereços relativos de seções ET_REL; a correção preserva
cada contexto de seção em vez de fingir uma imagem global carregada.

Os testes usam bytes sintéticos conhecidos de x86/x86_64/AArch64, entradas
em memória sem bytes, limite de instruções/amostra e o caminho real
filho → SQLite → relatório. O CI combinado exige a presença da dependência
real; não pode declarar a integração aprovada por pular seus testes.
A suíte base conserva o teste de funcionamento sem a dependência opcional.

### Validação positiva

No commit `cc292348046ba51fea219d2d52ee3cbce8a69453`, combinado pelo GitHub
com main `76ab1d4109f1366da404ed0dee25aeb945784b9d`:

- [Suíte base Windows, run 39039550942](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39039550942):
  189 testes descobertos, 183 executados e 6 pulados por ausência intencional
  do backend opcional; aprovação em 71,871 s.
- [Contratos combinados, run 39039550875](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39039550875):
  Capstone real 5.0.9 instalado em ambos os runners; Windows executou 255
  testes em 151,818 s; Linux descobriu 255, executou 253 e pulou os 2 testes
  específicos de Windows, em 25,581 s. Todos os executados passaram.
  Os três probes adicionais, demonstração e passagem item 4 → item 5
  também passaram nos dois sistemas.
- A combinação usa exclusivamente o candidato Claude imutável
  `70deac283947e2245af59e2a8709c5e525d3f7de` no runner descartável;
  não integra nem edita a branch Claude. As pendências F1–F5 do relatório
  geral continuam pertencendo à revisão desse candidato.
- A revisão independente de código do head cc292348 não encontrou novos
  pontos acionáveis após as correções de mapeamento. Foi revisão estática;
  a evidência de execução é dos workflows acima.

Esta seção registra o head validado antes desta atualização documental.
A atualização de recibos não altera o código validado.

Este incremento é uma prévia limitada. Não oferece desmontagem completa,
grafo de fluxo, símbolos/importações, decompilação Ghidra ou varredura
Binwalk; o item 6 integral permanece em andamento.

## Referências primárias

- [Capstone — API Python](https://www.capstone-engine.org/lang_python.html)
- [Código do binding usado, versão 5.0.9](https://github.com/capstone-engine/capstone/blob/5.0.9/bindings/python/capstone/__init__.py)
- [Distribuição 5.0.9 no PyPI](https://pypi.org/project/capstone/5.0.9/)
- [Estruturas de arquivo/endereço do incremento anterior](item-6-binary-structure.md)
