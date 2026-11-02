# Autorização e controle de acesso

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

A autorização deve ser decidida no servidor para cada operação e cada objeto, com base em identidade, papel, relação e contexto. Ocultar botão, mudar URL ou declarar escopo OpenAPI não prova que a API impõe o controle.

## Como revisar

Procure rotas sem verificação, checagem somente na interface, confiar em ID fornecido pelo cliente, permissões amplas por padrão e diferenças entre endpoints de leitura, alteração, exportação e exclusão. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Defina uma matriz sintética identidade × ação × objeto e compare permitido/negado em fixture. Confirme a identidade efetiva, o recurso alvo, estado e decisão do servidor. Não acesse dados reais de outros usuários. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Aplique negação por padrão, menor privilégio e política central consistente. Verifique permissão no ponto de acesso ao recurso e inclua vínculo do objeto à identidade. Reavalie cache, tarefas assíncronas e operações em lote. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Automatize matriz de permissões com contas sintéticas para dono, papel autorizado e não autorizado. Teste cada método e objeto; certifique que respostas negadas não alterem dados nem revelem conteúdo. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

RBAC simples pode não expressar relações e contexto. Contratos descrevem intenção, mas testes e revisão de implementação verificam imposição; não confunda ausência de evidência com prova de falha. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
