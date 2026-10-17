# Correções F1–F5 do candidato — 17/10/2026

Alterações autorizadas pelo proprietário após a revisão das 21 seções.
Branch própria codex/candidate-corrections, derivada do candidato imutável
70deac283947e2245af59e2a8709c5e525d3f7de; não altera a branch Claude.
O PR12 propõe as correções para esse candidato. A combinação com main existe
apenas no runner temporário, até uma integração explicitamente revisada.

## Comportamento

- F1: toda finding conserva linha, regra, severidade e excerpt string, mas
  excerpt contém mensagem fixa sem texto da origem. A detecção e a contagem
  continuam funcionando. Isso evita reexposição por outras regras e por
  sintaxes de segredo que a regex desconhece.
- F2: audit-config, analyze-capture, extract-strings e differentiate-content
  agora passam por autorização ativa, fila, cópia verificada e processo
  monitorado. Pausa impede novas chamadas antes de criar tarefa.
  O autoteste de envelope também revalida pausa antes de ler e publicar.
- F3: os quatro novos tipos persistem tarefas, resultados completos e digest
  de verificação; aparecem no relatório e sobrevivem a reinício. As findings
  de configuração persistidas já estão sem texto da origem. A cópia privada
  de evidência pode conter segredos; fica fora de Git, logs e artefatos do CI.
- F4: parsing de captura lê somente o teto da amostra e um byte indicador,
  sobre a cópia verificada. A aquisição e o hash ainda percorrem o arquivo
  inteiro dentro de max_bytes, deliberadamente: amostra não é aquisição parcial.
  As duas entradas declaram sample_truncated. Registro cortado é descartado
  explicitamente, sem tratar prefixo como mensagem completa. Tetos de IDs,
  payloads e comparação têm sinalização própria; IDs já conhecidos continuam
  sendo contados após saturar o inventário de IDs distintos.
- F5: domínios exigem igualdade ou sufixo delimitado por ponto. Um ponto DNS
  terminal é normalizado. O rótulo continua heurístico, offline e sujeito a
  verificação de autoridade; não comprova consulta, origem ou confiabilidade.

As análises já em execução mantêm a semântica anterior de pausa do worker:
pausa bloqueia trabalho novo; cancelamento/revogação descartam publicação
tardia. Isso é supervisão de ciclo de vida, não sandbox de privilégios/rede.

## Compatibilidade e limites

A CLI conserva os comandos existentes; wrappers síncronos retornam os campos
anteriores e acrescentam task_id. Filas podem retomar os parâmetros da amostra.
Nenhuma senha/chave é argumento novo. Não amplia formatos recuperáveis.
Não acrescenta login ao beta pessoal nem instala produto no PC do proprietário.

A inspeção/recuperação de envelopes e outros caminhos que manipulam material
criptográfico têm contratos próprios: esta entrega não os apresenta como
todos migrados para o processo de análise estática.

## Evidência executada

Testes antes da correção: head01e783b7954ad4b3879d7c5c4d69ae65fd1a7c75,
run39040699497, Linux: 242 descobertos, 19 falhas de asserção/subteste esperadas
e 2 skips de Windows. Reproduziu os cinco problemas; não foi falha de instalação.

Head e59c42a7e0684acda4c575f2283615898149a44c:
- [Candidato isolado 39041025950](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39041025950):
  Windows 246 executados OK em145,597s; Linux246 descobertos,244 executados,
  2 skips específicos de Windows, OK em21,833s.
- [Combinação 39041025931](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39041025931)
  com main4ca8b44b5250c760302137e3033ddcc7f571214c:
  Windows274 executados OK em102,167s; Linux274 descobertos,272 executados,
  2 skips de Windows, OK em22,580s. Capstone real instalado.
  Três probes de contrato, handoff item4→5 e demonstração passaram em ambos.

As 19 regressões novas incluem CLI sem reexposição, regras combinadas,
cópias verificadas, persistência/relatório, reinício, limite de amostra,
cancelamento tardio e recusa de pausa/revogação. Nenhum dado real de cliente,
segredo real ou chamada a provedor foi utilizado. A revisão independente do
patch final e os checks do head atualizado permanecem requisitos de entrega.

Este recibo registra o head anterior à atualização documental; não é
aprovação automática do PR3 nem declaração de plataforma completa.
