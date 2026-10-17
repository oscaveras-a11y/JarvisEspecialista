# Validação — processos monitorados beta

Desenvolvimento e testes exclusivamente pelo GitHub. Nenhum clone, instalação de dependência ou execução do projeto no computador do proprietário nesta entrega.

## Resultado por commit

**129 testes aprovados em 55,873 segundos, sem falhas, erros ou skips**, além da demonstração sintética aprovada. Head `5397e54d9fc2fe96ebd87bc383a990275fe37c41`, base do PR `60d8c846e4893bce20b23a320121d8ef6e895fac`. [Run 38994622908](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38994622908), [job Windows](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38994622908/job/117284321173).

São 15 testes novos além dos 114 da base: PID separado, aquisição real preservando original/hash, timeout com filho travado, cancelamento e revogação em processos reais, descendentes com pipes herdados ou saída redirecionada, limite de saída, resposta inválida, falha de processo, ambiente sem variável sintética de segredo, falha de instalação do monitor, interrupção do monitor, morte abrupta do pai e retomada de lease, e descendente criado durante o encerramento.

Também passaram instalação no runner temporário, `pip check`, compilação e CLI instalada. A demo manteve `platform_complete: false`. Não houve execução de arquivo de evidência, acesso a hardware, chamada real de agente ou envio de dado de cliente.

O resultado é vinculado ao commit citado. Atualizações posteriores de documentação também disparam CI: consultar os checks do [PR #4](https://github.com/oscaveras-a11y/CyberCore/pull/4) para o head mais recente. A integração com outro PR/branch não foi comprovada por esse resultado.

## Falhas verificadas e correção

1. O commit de testes antes da implementação produziu **13 falhas esperadas** pela ausência do supervisor no [run 38990034570](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38990034570).
2. A primeira implementação passou com 127 testes no [run 38993974669](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38993974669).
3. A revisão apontou possível liberação prematura de arquivos por descendentes. O teste novo **reproduziu WinError 32/PermissionError** após o supervisor retornar no [run 38994130883](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38994130883). Consultar só o exit code do processo não comprovava liberação de seus recursos. A correção aguarda handles SYNCHRONIZE antes da limpeza.
4. A hipótese adicional de processo criado entre enumeração e término não se reproduziu no ensaio específico: o [run 38994467654](https://github.com/oscaveras-a11y/CyberCore/actions/runs/38994467654) passou com 129 testes. Ainda assim, a implementação foi reforçada para aguardar confirmação de job vazio, cobrindo membros surgidos durante o encerramento. Não apresentar essa hipótese como uma falha que o teste comprovou.
5. A versão final com completion port passou novamente, conforme o primeiro resultado deste documento.

A revisão estática independente via GitHub não encontrou novos defeitos acionáveis no head validado. Não substitui testes reais nem revisão do Claude no seu próprio contexto. O [contrato da beta](analysis-process-beta.md) distingue controle de processos de sandbox de segurança e lista as limitações ainda existentes.
