# VisionFT/FTW2 — desenho e critérios de implementação

Estado: proposta para revisão; nenhuma capacidade implementada ou validada por este documento.
Base examinada: main de2fe897b7b2ef30033bc5edae952255b6b08bdf.
Data: 2026-10-23.

## Objetivo e autoridade

Preparar extração estática de instaladores NSIS, análise de executáveis desktop e inspeção de pacotes FTW2 com resultados persistentes no CORE. Não executar evidências. Não publicar instaladores, firmware, CAN, bancos ou resultados privados no GitHub público. Desenvolvimento e testes apenas no GitHub, com amostras sintéticas. Não alterar as branches existentes nem integrar o PR #3 do Claude, #22 do painel ou #25 de firmware por consequência desta entrega.

A seção 6 (engenharia reversa), ambiente, protocolos, execução, segurança e testes pertencem ao Codex. Mudanças estreitas nos contratos compartilhados do CORE serão aditivas, preservando memória, recuperação criptográfica e interface. Ver AGENTS.md e docs/project-ownership.md. Verificação de assinatura de pacote não amplia as rotinas de recuperação criptográfica da seção 7.

## Estado observado

- Core.__init__ usa padrão de 64 MiB e rejeita max_bytes acima de 256 MiB.
- firmware._read lê max_bytes + 1; _load retém os bytes e compare_firmware mantém as duas entradas.
- reverse_engineering.external.MAX_INPUT e MAX_SCRATCH são 64 MiB; há limites separados de stdio/JSON.
- Capstone preview tem teto de 4096 bytes e 128 instruções.
- ExportPreview.java exporta até oito funções em ordem, sem seletor.
- O adaptador Ghidra valida esquema e versão 12.1.4. A ampliação precisa atualizar produtor e consumidor juntos.
- O workflow external-backends já realiza análise sintética real em Ghidra/Binwalk e regressões Windows/Linux.
- Os arquivos reais não foram lidos nesta tarefa. Os hashes informados pelo proprietário são referências a conferir, não resultados reproduzidos.

## Abordagens

1. Aumentar apenas constantes: descartada; mantém cópias grandes e não resolve seleção, retomada ou extração.
2. Criar ferramenta independente: evita contratos centrais, mas duplicaria autorização, auditoria e fila; não atende integração pedida.
3. Ampliar os módulos existentes com leitores limitados e tarefas persistentes: proposta recomendada. Preserva prévias e validações atuais; exige migração aditiva de parâmetros e testes de contratos.

Escolha de implementação proposta: Python atual, scripts Ghidra confiáveis do pacote, Capstone existente e processo 7-Zip supervisionado; nenhuma extensão fornecida pela evidência é executada.

## Orçamento e arquivos grandes

Introduzir contrato serializável AnalysisBudget: input_bytes, chunk_bytes, memory_bytes, wall_seconds, scratch_bytes, extracted_bytes, output_bytes, max_entries, max_symbols, max_functions, max_instructions e max_references. Rejeitar negativos, booleanos, não finitos e limites incompatíveis antes de adquirir evidência.

Valores iniciais propostos: entrada 1 GiB; chunks 1 MiB; memória 2 GiB para análise nativa e processo Java separado até 2 GiB; prazo 30 minutos; scratch 8 GiB; extração 2 GiB; saída JSON 8 MiB; 10 mil entradas, 100 mil símbolos, 128 funções e 10 mil referências. São decisões propostas, configuráveis dentro de tetos administrativos; não garantem que qualquer executável caiba. Preservar padrões conservadores dos comandos antigos quando necessário e expor perfil explícito visionft.

Usar leitura por intervalos para headers e tabelas; hashing e cópia em chunks com checagem de prazo, cancelamento e tamanho durante o fluxo. Não usar lstrip/read_bytes sobre imagem inteira. mmap somente quando viável no orçamento de endereço virtual e com fechamento determinístico. Intel HEX/S-record mantêm limites de decodificação próprios. Comparação binária por chunks, ranges de diferença limitados, sem loop Python por byte de arquivo inteiro.

Aplicar os mesmos parâmetros em CLI, CORE, fila, aquisição, subprocesso, adaptadores e retomada. Processo externo com supervisor, encerramento de descendentes, limite de saída e monitor de scratch; distinguir limites rígidos de limites monitorados e overshoot possível. Falha/cancelamento remove parciais e não registra sucesso.

## NSIS / 7-Zip

Listagem por 7z l -slt, nunca execução do instalador. Validar envelope, tipo identificado e entradas com parser limitado. Listagem e extração são operações distintas, ambas com orçamento e versão real da ferramenta registrada.

Aceitar seleção explícita de VisionFT.exe e Firmwares/*.vftw, com match de caminho relativo normalizado. Rejeitar absolutos, drives, UNC, .., separadores ambíguos, nomes de dispositivo Windows, ADS, links, duplicatas e colisões por case folding. Não enviar nomes não validados como opções; não usar shell nem extração recursiva irrestrita. Extrair cada arquivo selecionado por stdout limitado para arquivo exclusivo em staging, sem permitir que o extrator escolha caminho de saída. Consultar tamanho declarado antes e contar bytes reais durante a gravação.

Nunca sobrescrever originais. Publicar staging atomicamente somente após sucesso, tamanho e hash verificados. Registro inclui SHA-256 do instalador, caminho interno exato, tamanho listado e extraído, hash extraído, parâmetros e versão 7-Zip. Tratar mudança da origem durante operação como falha de integridade. O suporte NSIS real será provado por instalador sintético criado com makensis no runner.

## COFF e C++

Ler PointerToSymbolTable/NumberOfSymbols, registros de 18 bytes, registros auxiliares e string table com aritmética de limites antes de alocação. Reconhecer explicitamente BigObj/variantes sem suporte. Distinguir endereço relativo à seção, RVA e VA; símbolos não provam limites de função. Rejeitar índices e nomes fora da tabela; limitar tamanho e quantidade.

Desambiguação opcional por llvm-cxxfilt/llvm-undname com nomes limitados, chamada sem shell e prazo compartilhado. Guardar nome original e nome apresentado, ferramenta/versão e falha individual. Sem ferramenta, manter nome original e status parcial. Amostras COFF reais compiladas pelo toolchain do runner, além de casos malformados construídos em testes.

## Qt / QML

Detectar recursos Qt e unidades QML compiladas a partir de identificadores estruturais verificados; strings isoladas são apenas candidatos. Cada decodificador declara versão, byte order, offsets e comprimentos aceitos. Não substituir parser por grep de strings.

Qt RCC e QML compilado são camadas distintas. Extrair recursos suportados e, em unidades conhecidas, strings, constantes, traduções, objetos e bindings sem executar QML. Para compactação, limitar tamanho expandido e taxa de expansão. Versão incompatível retorna unsupported_version com offsets dos candidatos; parser parcial identifica campos efetivamente lidos e campos não cobertos. Não alegar reconstrução do QML original.

A matriz de versões suportadas depende de fixtures produzidas por ferramentas Qt identificadas no runner. Primeiro suportar uma versão documentada e testada; demais variantes permanecem explicitamente pendentes.

## FTW2

Não há especificação de layout nem amostra FTW2 disponível nesta tarefa. A assinatura de quatro bytes identifica candidato, mas não define offsets, tamanhos, encoding, algoritmo, escopo assinado ou compressão.

Implementar camada de reconhecimento genérica e registro de variantes versionadas. Sem layout validado: status identified_layout_unknown; não ler campos por adivinhação nem chamar um envelope sintético inventado de FTW2 real. Para habilitar variante, exigir layout documentado com origem identificada, limites e vetores independentes autorizados. O parser genérico pode testar seu contrato com um formato de laboratório de nome distinto.

Quando variante conhecida: ler versão, alvo, manifesto, assinatura, comprimentos e tabela de segmentos; validar contagens, limites, marcadores, sobreposições permitidas explicitamente e consumo de bytes. Reconstruir em streaming para staging; lacunas, ordem, endereços e descompressão seguem apenas regras comprovadas da variante. Comparar SHA-256 reconstruído com hash declarado e reportar match/mismatch/not_comparable, incluindo interpretação e âmbito; mismatch não significa automaticamente corrupção.

Verificar assinatura somente com algoritmo e bytes assinados definidos pelo layout e chave pública fornecida ou extraída por procedimento documentado. Registrar fingerprint, origem e confiança da chave. Resultados independentes: assinatura criptográfica do cabeçalho, integridade do conteúdo reconstruído e vínculo da chave com fabricante. Chave embutida extraída do próprio pacote não comprova identidade do fabricante. Não presumir criptografia nem chamar reconstrução de descriptografia.

## Seletores e análise aprofundada

Preservar preview sem alteração semântica. Acrescentar seleção explícita por nome exato, endereço de função e intervalo semiaberto, com política clara de interseção. Resolver nomes duplicados com lista de candidatos. Não transformar qualquer endereço em função sem informar que é intervalo de instruções.

Ghidra recebe arquivo de seleção validado produzido pelo CORE, nunca script da evidência. Exportador próprio seleciona funções, decompila com prazo por função e global, exporta chamadas de entrada/saída e referências tipadas limitadas. Atualizar validação JSON junto; status por função e truncamentos explícitos. Pseudocódigo sempre identificado como interpretação do decompilador, não fonte original.

Capstone usa mapeamento de seções já validado, sem cruzar limites ambíguos, com bytes/instruções configuráveis. Referências indiretas não resolvidas são reportadas como tal. Nenhuma análise implica execução ou prova de comportamento em veículo.

## Comparação

Comparar hashes e bytes, cabeçalhos normalizados, recursos QML suportados e funções escolhidas. Parear por símbolo único e confirmação explícita quando ambíguo. Preservar diferença bruta.

Normalização de endereço/relocação apenas em operandos e relocations identificados estruturalmente; não apagar immediates arbitrários. Resultados: diferença bruta, diferença possivelmente atribuível a realocação, possível mudança de lógica e inconclusivo. Documentar arquitetura, versão de ferramenta e limites. Sem equivalência semântica garantida nem afirmação de correção no veículo.

## CORE, persistência e retomada

Usar autorização, aquisição verificada, fila, supervisão, auditoria e relatório existentes. Persistir tipo de etapa e parâmetros numa migração aditiva; não contornar serviço com CLI isolada. Referenciar entradas por hash, resultados por digest e ferramentas por versão.

Checkpoint somente em fronteiras concluídas: aquisição, listagem, extração individual, metadados, função individual, comparação e relatório. Ao retomar, conferir hash de entrada, parâmetros, schema, versões e integridade dos resultados; se mudaram, invalidar etapa e dependentes. Não retomar bytes parciais de extração como arquivo válido. Cancelamento mantém estado auditável sem publicar parciais.

Relatórios têm seções comprovado, hipótese e pendente; distinguem versão não suportada, orçamento esgotado e erro de formato. Resultados privados ficam em diretório operacional fora de Git e de uploads do CI.

## Ordem e testes de aceitação

1. Orçamento e leitores grandes: regressões existentes + fixtures esparsas de pelo menos 600 MiB e 250 MiB, streaming e pico de memória medido, comparação interrompível.
2. NSIS: makensis cria fixture contendo VisionFT.exe e Firmwares/lab.vftw sintéticos; 7-Zip real lista e extrai somente seleção. Testar travessia, links, colisões, contagens e bombas de expansão.
3. COFF/Qt: compilar COFF C++ e recursos Qt/QML sintéticos com ferramentas reais e versões registradas. Testar strings longas, auxiliares e tabelas truncadas, offsets e versões inválidas.
4. Seleção Ghidra/Capstone: binário sintético com funções conhecidas, chamadas e referência a constante. Teste real exige encontrar função pedida e conteúdo esperado; não basta --version. Testar nome inexistente/ambíguo, intervalo inválido e orçamento esgotado.
5. FTW2: reconhecimento e rejeição de layout desconhecido; contrato de variante com formato de laboratório separado. Leitor de variante real depende de especificação verificável. Testar comprimento, contagens, marcadores, segmentos e assinatura inválida em cada variante efetivamente suportada.
6. CORE: persistir/reabrir/retomar com cancelamento e mudança de parâmetros; validar comparação e relatório; regressões Windows/Linux e integrações reais no Linux conforme suporte atual.

Jobs não recebem VisionFT, segredos ou evidência do usuário. Não fazer upload de dumps, resultados de decompilação ou arquivos extraídos. Logs imprimem apenas resultados de fixtures sintéticas. Workflow precisa rodar no SHA exato do PR e links são registrados junto da entrega. Falha de provisionamento é bloqueio de validação, nunca aprovação.

## Critérios de conclusão e limites atuais

Entrega final exigirá código, branch própria, PR, testes com links e comandos efetivamente exercitados. Instalar ferramentas ou escrever esta proposta não cumpre a tarefa.

Nenhuma análise do VisionFT real foi realizada. Os tamanhos 481337928 e 200282456 e os hashes fornecidos são referências externas. Seleções DSG v2=3, DSG=2 e filtro Somente conhecidas permanecem não reproduzidos pelo Jarvis.

Pendência técnica que não pode ser resolvida inventando fixture: layout FTW2 real e variantes Qt/QML do executável real. Ausência desses dados não bloqueia infraestrutura e testes sintéticos, mas impede declarar análise correspondente concluída.

## Revisão técnica e decisões adicionais

Revisão de viabilidade feita por agente separado, sem execução do produto. Não equivale a revisão independente autenticada ou teste.

- Memória: no Linux, limitar árvore por cgroup quando disponível, além do limite de heap Java e limites por processo. Medir memory.peak do grupo no CI; quando não disponível, registrar método alternativo e não declarar teto agregado rígido. Windows depende do supervisor existente e suporte verificável de Job Objects; sem controle agregado testado, reportar limitação e manter as integrações externas no Linux.
- NSIS sólido: o orçamento cobre tempo de descompressão total, scratch e disco temporário do extrator, mesmo quando só um arquivo sai por stdout. A fixture de integração inclui compressão sólida e arquivo selecionado após outros dados.
- Entrada: ferramentas consomem a cópia adquirida/verificada em diretório operacional protegido contra escrita concorrente. Conferência pré/pós é detecção adicional, não proteção contra alteração transitória por agente com os mesmos privilégios. Não prometer isolamento desse adversário.
- Qt inicial: começar com RCC e unidades compiladas geradas por Qt 6.8.3, ferramentas rcc e qmlcachegen identificadas no runner. Confirmar disponibilidade/licença/provisionamento antes de implementação. Se o formato interno não puder ser validado por fonte e fixture real, suportar apenas RCC comprovado e marcar campos QML como não suportados. Nenhuma fixture manual sozinha comprova compatibilidade com Qt real.
- Mudança de versão de ferramenta invalida etapa e dependentes por padrão; histórico permanece consultável, mas não é reutilizado automaticamente.
- Evidências em três níveis separados: testes unitários sintéticos; ferramentas reais sobre fixtures sintéticas geradas; análise privada do VisionFT. A entrega não pode misturar os níveis.
- FTW2 real: leitura de campos, reconstrução e assinatura permanecem requisitos incompletos até layout verificável. Mesmo CI totalmente verde não encerra esses itens.
