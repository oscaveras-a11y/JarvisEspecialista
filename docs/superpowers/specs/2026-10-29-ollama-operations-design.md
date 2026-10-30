# Agente operacional Ollama no Jarvis — desenho para aprovação

## Intenção e decisões do proprietário
Integrar o Qwen3 1.7B via Ollama ao próprio Jarvis para realizar operações, e não apenas revisar texto externamente. O proprietário escolheu executar automaticamente ferramentas já autorizadas no caso, sem confirmação a cada chamada. Deseja colaboração em pentest e recuperação de senhas. Não há autorização para merge.

## Base e responsabilidade
Base imutável: PR34, 19bafbe1b94cfb87645e0cc784f87df4bd6e8cc0. Branch própria codex/ollama-operations. Preservar PR33/34 e branches Claude.
Integração pertence ao raciocínio/execução/testes das seções pares. Não substituir contratos de agentes, memória, recuperação ou UI das seções ímpares. Consumir suas APIs existentes; alterações compartilhadas estreitas devem ser revistas. Desenvolvimento e execução do produto somente em runners GitHub com entradas sintéticas. Ollama instalado no computador não autoriza executar o produto localmente nesta entrega.

## Abordagens
1. Agente operacional via protocolo estruturado e dispatcher CORE: escolhido conforme pedido de execução automática autorizada. Mais integração e validação, com auditoria/reentrada existentes.
2. Chat consultivo que apenas sugere ações: menor esforço, mas não satisfaz o pedido e foi expressamente rejeitado.
3. Modelo emitindo shell livre: não adotado; contorna contratos e torna resultados/cancelamento difíceis de verificar.
O transporte loopback HTTP, limites e implementação abaixo são propostas do implementador, não preferências expressamente ditadas pelo proprietário.

## Fluxo proposto
Comando CLI específico inicia ciclo do agente no caso autorizado. Cada ciclo fornece objetivo e resumo mínimo estruturado, catálogo de ferramentas realmente disponíveis, IDs opacos de recursos registrados e resultados sanitizados anteriores. Qwen3 responde JSON com uma ação permitida ou parada justificada. Dispatcher valida esquema, argumentos e vínculo ao caso, reautoriza, executa pela API pública correspondente, registra recibo e devolve resultado sanitizado ao modelo.
Nenhuma interpretação de texto como código, eval, shell, caminho ou URL livres. Identidade do operador vem da autorização existente, nunca da fala do modelo. Prompt/resposta do modelo não concedem permissão.

## Primeiro incremento operacional
- Selecionar e executar campanha API de laboratório previamente registrada, usando spec, grant, matriz e CA fixados pelo caso e pelos hashes; consultar seu progresso/resultado.
- Consultar formatos disponíveis e iniciar/continuar trabalho de sessão de recuperação previamente registrada pelo proprietário, com alvo e lista de candidatas já autorizados e identificados por ID. Não enviar conteúdo das candidatas, senhas, arquivos ou chaves ao modelo. Não gerar/alterar listas nesta entrega.
- Consultar resumos sanitizados de operações e parar com motivo.
- Nenhuma criação automática de novos alvos, grants, contas, autorização, revogação, desbloqueio de casos ou reabertura de sessão resource_limited. Resolver dependência exige decisão explícita; o agente reporta bloqueio.
Os nomes exatos de métodos e comando CLI serão definidos no plano após inspeção das APIs. Não criar backends de recuperação novos, pesquisa web, ferramentas ausentes ou login em sites. Testes HTTP permanecem limitados ao laboratório do PR34.

## Modelo e transporte
Ollama opcional em endpoint loopback explícito; Qwen3 1.7B, thinking desativado por padrão, modelo configurável por opção validada. Sem fallback para nuvem nem exposição pública do serviço. Chamadas limitadas em tempo/bytes/tokens e canceláveis; redirecionamentos e proxies desabilitados. Servidor ausente ou modelo incorreto são dependências indisponíveis, não resultado operacional.
Proposta inicial: até 8 decisões por invocação, 300 segundos totais, 1024 tokens de contexto e até 320 tokens de saída por decisão; parâmetros ajustáveis dentro de limites validados. O montador de contexto deve verificar orçamento e recusar/truncar campos opcionais explicitamente, preservando sempre contrato e autorização. Testar se o pequeno contexto é suficiente; se não for, registrar bloqueio em vez de executar ação ambígua.
Sem garantia de inteligência suficiente por ter passado em benchmark simples. Refusamentos e respostas ruins viram parada identificada, sem contornar controles ou falsificar execução.

## Persistência e ciclo de vida
Estado aditivo separado, sem alterar esquema global ou interfaces Codex/Claude. ID de ciclo/decisão e recibos vinculados ao caso, parâmetros e hashes. Reserva antes de execução, adoção de resultados publicados após interrupção. Recuperação usa seus checkpoints/leases, campanhas seus recibos. Efeitos parciais podem existir antes de publicação: não afirmar exactly-once de rede; não repetir silenciosamente operação ambígua.
Rechecar autorização, validade, pausa, cancelamento e propriedade na reserva e antes da publicação. Cancelamento interrompe chamada ao modelo e worker pelos mecanismos existentes; resultado tardio não é publicado. Limites por caso e por ferramenta continuam valendo mesmo quando o modelo solicita mais.

## Evidências e senhas
Registros distinguem proposta/inferência da IA, operação executada, observação, alerta e falha confirmada. Senha candidata só é confirmada pelo backend aplicável, nunca por afirmação do modelo. Não registrar senha encontrada, candidatas, tokens, corpos privados ou arquivos desbloqueados em logs, Git, relatórios ou CI. A confirmação usa o contrato atual da sessão e método de validação.
Sem promessa de recuperar qualquer senha, quebrar criptografia ou concluir pentest integral. authentication/authorization independentes e outras etapas ausentes continuam explicitamente indisponíveis.

## Validação e entrega
Testes RED/GREEN de protocolo, JSON inválido, nomes/argumentos desconhecidos, escopo/caso trocado, injeção em conteúdo, ferramenta ausente, modelo ausente, timeout, saída excessiva, orçamento/contexto, loop repetitivo, pausa/revogação/cancelamento, concorrência, queda e retomada.
Integrações GitHub Linux/Windows com transporte sintético determinístico e ferramentas reais usando fixtures sintéticas. Ensaio separado Linux com Ollama e Qwen3 reais, sem credenciais, para comprovar resposta do modelo e ao menos uma operação CORE efetivamente executada; se o modelo não produzir ação válida, reportar falha/bloqueio, sem converter em sucesso com resposta fabricada. Modelo real não precisa ser determinístico nem ter todos os casos de erro simulados.
Regressões completas e fluxos existentes. Documentar skips, links e SHA exato. PR draft revisável, sem merge. Critério de entrega: integração operacional demonstrada em CI, não instalação no computador nem operação real do beta.

## Decisões delegadas ao implementador e pendência
Delegados: nomes de APIs/comandos/tabelas, esquema JSON mínimo, implementação do transporte isolado, sanitização e fixtures de teste, respeitando estes contratos. Questões de API descobertas no plano devem preservar os dois lados.
Pendente: aprovação deste desenho pelo proprietário antes de código de produto. O proprietário já autorizou execução automática de operações autorizadas; essa escolha não será perguntada novamente.

## Direção ampliada confirmada pelo proprietário
Após a proposta inicial, o proprietário esclareceu que quer um agente trabalhando dentro do Jarvis como um agente de programação: receber objetivos, usar ferramentas, escrever código, executar testes, interpretar erros e continuar a tarefa. Confirmou que memória e treinamento serão melhorados depois. A primeira entrega operacional acima é um incremento dessa direção, não a totalidade do agente pretendido.

Sequência registrada:
1. Integração operacional Ollama/CORE com execução automática autorizada e evidências reais de funcionamento.
2. Ferramentas de programação em ambiente de desenvolvimento isolado: alterações revisáveis, execução de testes e iteração com resultados. Requer desenho específico de workspace, ferramentas e publicação antes de implementar; não está entregue pelo dispatcher do primeiro incremento.
3. Memória persistente consumindo os contratos existentes da seção 5, preservando proveniência e separando objetivo, hipótese e fato validado. A recuperação de contexto não altera os pesos do modelo.
4. Avaliação de treinamento/adaptação com exemplos selecionados, direitos de uso e conjunto de testes separado. Não treinar automaticamente com conversas, senhas, evidências privadas ou erros promovidos a exemplos corretos. Dados operacionais permanecem fora do Git/CI.

Modelo com menos recusas indevidas é uma preferência do proprietário; não há garantia de ausência universal de recusas ou equivalência de capacidade com Codex. Não foi realizado treinamento, mudança de pesos ou memória nova nesta atualização. O pequeno hardware local não comprova capacidade de treinamento; escolher ambiente e técnica apenas na etapa correspondente. Os detalhes de memória e treinamento ficam para desenhos posteriores, respeitando a divisão Codex/Claude.
