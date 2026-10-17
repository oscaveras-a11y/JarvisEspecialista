# Responsabilidade por seções do projeto

Divisão confirmada pelo proprietário nesta conversa: a numeração é a das **21 seções do documento original**, não a das nove fases.

| Responsável | Seções |
|---|---|
| Codex | 2 — ambiente; 4 — raciocínio e investigação; 6 — engenharia reversa; 8 — perícia; 10 — protocolos; 12 — execução prolongada; 14 — segurança do sistema; 16 — estrutura do repositório; 18 — testes; 20 — critérios de entrega |
| Claude | 1 — missão; 3 — CORE e agentes; 5 — memória; 7 — criptografia/recuperação; 9 — vulnerabilidades; 11 — pesquisa; 13 — verificação independente; 15 — interface; 17 — integração GitHub; 19 — fases; 21 — instrução final |

A divisão atribui funcionalidades e revisão de contratos; não transforma um arquivo compartilhado em dois arquivos independentes. Ajustes estreitos de integração em `service.py` devem preservar os contratos das outras seções e ser revistos antes da integração. Cada agente trabalha em sua própria branch e PR. Não editar ou integrar automaticamente a branch do outro agente.

A orientação atual de ambiente prevalece sobre o plano local inicial: desenvolvimento e testes desta entrega **somente no GitHub**, sem instalar ou executar o projeto no computador do proprietário. Usar somente entradas sintéticas/autorizadas nos testes; nenhum segredo ou evidência de cliente deve ir para o repositório ou CI.

## Controle do beta

O proprietário é o único usuário e administrador previsto do beta; Codex e Claude continuam desenvolvendo e testando nas tarefas autorizadas, sem aprovação individual a cada execução. O proprietário decidiu testar o funcionamento primeiro, **sem login da aplicação nesta fase**. A [política de testes pessoais](beta-access.md) adia a autenticação e preserva o trabalho autorizado dos agentes. As instruções comuns estão em [AGENTS.md](../AGENTS.md).

## Entregas Codex

[PR #4](https://github.com/oscaveras-a11y/CyberCore/pull/4), integrado na main em `3d5329066e41fdb585520182abc8f3522410589f`: supervisão de processos de análise (seções 12 e 14), seus testes (18), documentação/entrega (16 e 20). Não acrescenta funcionalidades de criptografia, interface, memória ou pesquisa das seções ímpares.

O [PR #3 do Claude](https://github.com/oscaveras-a11y/CyberCore/pull/3) também modifica contratos centrais. O [PR #5](https://github.com/oscaveras-a11y/CyberCore/pull/5) verifica a combinação com o candidato imutável `c5f87f363bcc472e4087636ce29c366aefe95e28` somente em runners descartáveis, corrigindo as fronteiras de prazo e interrupção das seções pares. Veja [resultados e limites](integration-contracts.md). Isso não integra nem aprova automaticamente o PR do Claude; qualquer novo head ou alteração de contrato exige avaliação da versão correspondente.

[PR #6](https://github.com/oscaveras-a11y/CyberCore/pull/6): item **4 — motor de raciocínio e investigação** concluído no [contrato operacional e mapa das 15 etapas](item-4-reasoning.md), com API persistente documentada para o item 5. Validação da base Windows e combinação Windows/Linux com o candidato Claude `00adab4ccc187f517ee8272a29e285087b54e347`, incluindo reabertura, recall e relatório. O trabalho do Claude permanece na branch dele.

Concluir uma beta delimitada não significa concluir todas as obrigações de uma seção. O resultado de testes e os requisitos pendentes devem ser apresentados separadamente.
