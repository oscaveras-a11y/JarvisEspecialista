# Segredos e configuração

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Segredos incluem chaves, tokens, certificados, senhas de serviço e material de assinatura. Minimize criação e circulação, injete em tempo de execução por mecanismo aprovado, limite escopo e mantenha rotação e revogação praticáveis.

## Como revisar

Revise arquivos de ambiente servidos pela web, repositórios, logs, artefatos de build, mapas de fonte, variáveis de CI e configurações padrão. Identifique também segredos compartilhados, sem expirar e com privilégios maiores que a tarefa. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Use scanners e inspeção de metadados em repositório de teste; nunca copie o valor para ticket ou relatório. Se houver exposição real, trate-a como comprometimento potencial e coordene revogação pelo canal autorizado. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Remova segredo do código e histórico conforme processo, revogue e substitua credenciais, armazene em cofre ou secret store, conceda menor privilégio e audite acesso. Separe ambientes e evite devolver segredos ao cliente ou registrar em texto. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Inclua secret scanning em CI e testes que verifiquem que artefatos e logs não contêm marcadores sintéticos. Teste rotação e revogação em ambiente controlado. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Apagar uma linha atual não invalida cópias já distribuídas. O procedimento de remoção histórica não substitui rotação; preserve trilha necessária sem expor o valor. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
