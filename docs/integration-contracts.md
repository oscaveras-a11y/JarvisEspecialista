# Compatibilidade das entregas de execução

Escopo: seções pares 12, 14, 18 e 20. Base Codex: PR #4 integrado em
`3d5329066e41fdb585520182abc8f3522410589f`. Candidato Claude:
`c5f87f363bcc472e4087636ce29c366aefe95e28` (PR #3).

## Plano e critérios

1. Combinar esses contratos somente no runner descartável do GitHub, sem push
   do resultado da combinação e sem escrever na branch do Claude.
2. Reproduzir um arquivo sintético processado com orçamento de 86400 segundos
   e uma interrupção com limite de uma tentativa. Preservar também a retomada
   quando o limite é maior que três.
3. Corrigir somente as fronteiras de execução: supervisor e filho devem
   aceitar o teto de sanidade já escolhido no candidato (365 dias);
   interrupção deve consultar o limite efetivo de tentativas.
4. Executar a suíte completa da base própria e a combinação em Windows e
   Linux, além das sondas específicas e da demonstração sintética.
5. Registrar resultados, limites e revisão independente antes da entrega.

Arquivos: `analysis_process/supervisor.py`, `analysis_process/child.py` e
`analysis_process/limits.py` para o mesmo teto; ajuste estreito de
`service.py` para interrupções. Testes em `tests/test_process_contracts.py`
e `scripts/check-integration-contracts.py`. O workflow separado
`.github/workflows/integration-contracts.yml` fixa o candidato por SHA.

Nenhuma instalação ou execução do projeto no computador do proprietário.
Nenhuma mudança de memória, interface, criptografia ou agentes do Claude.
Esta verificação não aprova nem integra o PR #3.

## Reprodução anterior à correção

[Run 39028515975](https://github.com/oscaveras-a11y/CyberCore/actions/runs/39028515975),
combinação no Linux: a suíte descobriu 157 testes, com uma falha e dois
skips exclusivos do Windows. As duas sondas adicionais reproduziram:

- Prazo de 86400 aceito no Core, mas rejeitado no supervisor ainda limitado a
  3600: `Invalid analysis process timeout`.
- Interrupção na primeira tentativa com limite configurado em 1: estado
  `pending` em vez de `failed`, devido ao valor 3 fixo no handler.

A falha da suíte foi a exigência de término imediato de descendente com
arquivo aberto. O código POSIX envia SIGKILL ao grupo e retorna; não oferece
a espera de handles/Job Object do Windows. O teste será explícito: término
imediato continua obrigatório no Windows; no POSIX exige-se término em
até cinco segundos. Não é uma nova garantia de sandbox ou morte do pai.

## Resultado final

Correções e revisão estática independente concluídas no head
`ec5344d0b85cb9e57eab1b7e1e45fc48d03126e9`, sem novos achados acionáveis.
A revisão leu o código pelo GitHub; execução comprovada pelos jobs abaixo.

| Conjunto | Plataforma | Descobertos | Executados | Skips | Resultado |
|---|---|---:|---:|---:|---|
| Base própria do PR #5 | Windows | 132 | 132 | 0 | OK em 59.659s |
| Combinação com candidato fixado | Windows | 160 | 160 | 0 | OK em 80.702s |
| Combinação com candidato fixado | Linux | 160 | 158 | 2 | OK em 17.313s |
| Sondas de integração, adicionais à suíte | Windows | 3 | 3 | 0 | OK em 1.657s |
| Sondas de integração, adicionais à suíte | Linux | 3 | 3 | 0 | OK em 0.150s |

[Validação da base própria](https://github.com/oscaveras-a11y/CyberCore/actions/runs/39028689597)
e [validação combinada](https://github.com/oscaveras-a11y/CyberCore/actions/runs/39028689568).
Instalação no runner, dependências, compilação, CLI e demonstrações aprovadas.
Os dois skips Linux são específicos de Job Objects: morte do pai e membro
criado durante encerramento. Eles foram executados e passaram no Windows.

O supervisor e o filho compartilham o teto de sanidade de 365 dias, preservando
o orçamento individual menor recebido do chamador. A base pública atual ainda
limita o Core a 3600 segundos; aceitar prazo maior pelo Core depende da
configuração do candidato, que não é integrada por este PR. Interrupções
usam `max_attempts` quando configurado e preservam o padrão 3 na base atual.
Não mudam os contratos de cancelamento nem a publicação transacional.

A combinação por SHA é evidência de compatibilidade desses commits, não de
qualquer versão futura da branch. A suíte não representa uma análise
exaustiva de segurança nem conclui todas as seções do projeto. A evidência de
24 horas é um arquivo pequeno com esse orçamento; não é uma execução de
24 horas. Permanecem os limites documentados de sandbox, CPU/RAM, boot,
morte abrupta do pai em POSIX e coleta automática de cópias órfãs.
