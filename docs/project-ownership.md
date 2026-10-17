# Responsabilidade por seções do projeto

Divisão confirmada pelo proprietário nesta conversa: a numeração é a das **21 seções do documento original**, não a das nove fases.

| Responsável | Seções |
|---|---|
| Codex | 2 — ambiente; 4 — raciocínio e investigação; 6 — engenharia reversa; 8 — perícia; 10 — protocolos; 12 — execução prolongada; 14 — segurança do sistema; 16 — estrutura do repositório; 18 — testes; 20 — critérios de entrega |
| Claude | 1 — missão; 3 — CORE e agentes; 5 — memória; 7 — criptografia/recuperação; 9 — vulnerabilidades; 11 — pesquisa; 13 — verificação independente; 15 — interface; 17 — integração GitHub; 19 — fases; 21 — instrução final |

A divisão atribui funcionalidades e revisão de contratos; não transforma um arquivo compartilhado em dois arquivos independentes. Ajustes estreitos de integração em `service.py` devem preservar os contratos das outras seções e ser revistos antes da integração. Cada agente trabalha em sua própria branch e PR. Não editar ou integrar automaticamente a branch do outro agente.

A orientação atual de ambiente prevalece sobre o plano local inicial: desenvolvimento e testes desta entrega **somente no GitHub**, sem instalar ou executar o projeto no computador do proprietário. Usar somente entradas sintéticas/autorizadas nos testes; nenhum segredo ou evidência de cliente deve ir para o repositório ou CI.

## Entrega Codex em andamento

[PR #4](https://github.com/oscaveras-a11y/CyberCore/pull/4), `codex/analysis-process-beta`: supervisão de processos de análise (seções 12 e 14), seus testes (18), documentação/entrega (16 e 20). Não acrescenta funcionalidades de criptografia, interface, memória ou pesquisa das seções ímpares.

O [PR #3 do Claude](https://github.com/oscaveras-a11y/CyberCore/pull/3) também modifica contratos centrais. Os testes desta entrega comprovam a base declarada no próprio PR; não comprovam a combinação de ambos os PRs. Qualquer combinação deve preservar as alterações dos dois lados e executar novamente a suíte, especialmente configuração, prazos, notas/hipóteses e versão SQLite.

Concluir uma beta delimitada não significa concluir todas as obrigações de uma seção. O resultado de testes e os requisitos pendentes devem ser apresentados separadamente.
