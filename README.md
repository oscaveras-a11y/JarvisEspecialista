# CYBER CORE

Plataforma de investigação digital **autorizada**, em desenvolvimento. Núcleo em Python 3.12+ e SQLite, com CLI e módulos de análise offline. Repositório privado [oscaveras-a11y/JarvisEspecialista](https://github.com/oscaveras-a11y/JarvisEspecialista), com histórico anterior preservado.

**Fluxo atual: desenvolvimento e validação somente no GitHub. Nenhuma instalação no computador do proprietário é necessária para acompanhar esta entrega.**

**Política do beta:** uso e administração reservados ao proprietário; Codex e Claude continuam desenvolvendo e testando. Nesta fase, o proprietário quer [testar o funcionamento sem login adicional da aplicação](docs/beta-access.md). Autenticação fica adiada e não é requisito para seu teste pessoal.

## Desenvolvimento no GitHub

1. As alterações são feitas em branches e apresentadas em pull requests para a `main`.
2. O workflow [Offline validation](.github/workflows/ci.yml) executa a validação em um runner Windows hospedado pelo GitHub, com Python 3.12.
3. O runner instala o pacote e suas dependências no ambiente temporário do GitHub, verifica dependências, compila as fontes, verifica a CLI instalada, executa `python scripts/run-tests.py` e `python scripts/demo.py`.
4. Consulte a aba **Checks** do PR ou [Actions](https://github.com/oscaveras-a11y/JarvisEspecialista/actions) para ver resultados e logs. Uma execução pendente ou ausente não significa aprovação.
5. A integração na `main` permanece uma etapa separada de revisão. Este workflow não configura proteção de branch nem faz merge automático.

O workflow roda em PRs para a `main` e em pushes para `main` e `codex/github-validation`. O disparo manual estará disponível na interface quando o workflow estiver na branch padrão. Há limite de 20 minutos por job e cancelamento de execuções anteriores do mesmo evento/ref após nova atualização.

Os testes usam arquivos sintéticos. Nenhuma credencial de Codex/Claude, chave de API ou evidência de cliente é necessária. O workflow não executa `scripts/agent-smoke.py`, não instala CLIs de agentes e não faz chamadas aos provedores de IA. As instalações de dependências usam a rede; a suíte de investigação é offline.

GitHub Actions valida o software em ambientes temporários; a plataforma ainda não oferece um serviço de investigação hospedado e persistente no GitHub. Bancos, evidências e relatórios operacionais de clientes devem permanecer fora do repositório e dos logs de CI. Não use os runners desta entrega para investigar dados de clientes.

## Funcionalidades existentes

- CLI para investigações, autorização e escopo, fila, pausa e retomada manual.
- SQLite com migrações, checkpoints, histórico e trilha de auditoria.
- Cópias verificadas, SHA-256, entropia, identificação de assinaturas e triagem de recuperação por arquivo ou lote, sem exigir chave fornecida.
- Hipóteses versionadas, experimentos com critérios declarados, avaliação de resultados auditados e revisão independente declarada.
- Análise e comparação offline de BIN, Intel HEX, S-record e estruturas ELF/PE: arquitetura declarada, seções e segmentos, com limites documentados.
- Integração opcional de Ghidra/Binwalk reais ao CORE e relatório, com [ensaios somente no GitHub](docs/real-tools-core.md).
- Prévia opcional de instruções com Capstone para arquiteturas declaradas compatíveis, limitada a bytes respaldados pelo arquivo; nunca executa o binário.
- Análise e comparação de logs CAN clássicos, sem acesso a barramentos ou transmissão.
- Recuperação autenticada AES-GCM somente do envelope sintético de laboratório `CCAES1`, quando material legítimo está disponível.

Uma assinatura não comprova validade integral do formato; alta entropia não comprova criptografia. A triagem não demonstra descriptografia e não há promessa universal de recuperação.

## Agentes e limites

O núcleo funciona sem agentes. O adaptador Codex e a chamada real sintética têm um registro histórico em [validação](docs/validation.md); esse registro não comprova autenticação ou funcionamento no runner atual. O envio de resumo exige autorização explícita. Claude permanece opcional e bloqueado até validação do contrato.

O sandbox do CLI é dependência externa. Nomes de revisores são declarações, não identidades autenticadas. A [orquestração beta](docs/orchestration-beta.md) acrescenta worker com limites, checkpoints e cancelamento persistente, validada em amostras sintéticas pelo GitHub Actions. O comando `run` continua processando uma tarefa. As quatro análises permitidas já usam processo monitorado; isso controla seu ciclo de vida, sem sandbox de privilégios/rede. Serviços de boot, worktrees por tarefa, revisão cruzada automática e integrações profissionais adicionais continuam pendentes.

**A plataforma completa ainda não foi entregue.** Testes aprovados comprovam apenas o comportamento coberto, não a prontidão de módulos profissionais ou ensaios com hardware.

## Documentação

- [Revisão das 21 seções e pendências, com versões examinadas](docs/2026-10-17-project-status-report.md)
- [Item 6: estruturas ELF/PE](docs/item-6-binary-structure.md)
- [Item 6: prévia opcional Capstone](docs/item-6-capstone.md)

- [Referência técnica da CLI para uso futuro](docs/cli-reference.md)
- [Orquestração beta: worker, pausa, cancelamento e limites](docs/orchestration-beta.md)
- [Estado das fases e próximos critérios](docs/roadmap.md)
- [Validação e resultados históricos](docs/validation.md)
- [Limites de segurança](docs/security.md)
- [Cobertura real de recuperação](docs/recovery-coverage.md)
- [Ciclo científico](docs/scientific-workflow.md)
- [Análise de firmware](docs/firmware.md)
- [Análise CAN](docs/can.md)

Referências da automação: [actions/checkout](https://github.com/actions/checkout), [actions/setup-python](https://github.com/actions/setup-python) e [eventos do GitHub Actions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

## Teste dos módulos de recuperação, perícia e agentes

Consulte [o guia do beta e suas pendências externas](docs/pending-modules-beta.md) para os comandos, limites e teste pelo GitHub Actions. Os agentes só terão comunicação real validada após configuração das credenciais pelo proprietário e resposta efetiva dos provedores.
