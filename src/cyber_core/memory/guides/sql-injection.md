# Prevenção de injeção SQL

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

O risco surge quando dados variáveis são interpretados como parte da sintaxe SQL. Separe estrutura da consulta e valores com parâmetros vinculados ou ORM corretamente usado; validar uma string não transforma concatenação em parametrização.

## Como revisar

Revise concatenação ou interpolação de dados em SQL, filtros e ordenações dinâmicas, consultas administrativas e usos inconsistentes do ORM. Veja se nomes de coluna ou direção de ordenação vêm de entrada e se a aplicação usa conta de banco com privilégios excessivos. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Confirme a construção da consulta no código e demonstre a separação entre comando e parâmetros em teste isolado com banco sintético. Verifique caminho alcançável e permissões. Não execute testes contra serviço real ou dados de terceiros. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Use prepared statements, parâmetros vinculados e mapeamentos fechados para identificadores dinâmicos. Restrinja privilégios da conta, separe papéis de leitura e escrita e trate erros sem revelar consulta, esquema ou valores. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Adicione regressão que confirme que entradas especiais são tratadas como valores, além de testes para filtros permitidos, controle de acesso e falhas do banco. Use banco descartável e conteúdo inventado. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Escapar manualmente é dependente de driver e codificação e não substitui parâmetros. Um scanner pode apontar concatenação sem demonstrar alcance; analise a API concreta e o fluxo completo. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
