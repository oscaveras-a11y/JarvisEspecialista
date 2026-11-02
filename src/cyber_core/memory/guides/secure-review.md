# Revisão segura de código

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

A revisão segura começa pelo contexto: dados, limites de confiança, identidades, permissões, dependências e consequências de falha. Leia o fluxo completo desde a entrada até o efeito persistente, sem inferir vulnerabilidade apenas por uma palavra ou padrão isolado.

## Como revisar

Procure entradas que mudem consultas, caminhos, comandos, permissões ou conteúdo exibido; decisões de autorização ausentes; segredos em configuração; validação somente no cliente; erros que exponham dados; e diferenças entre o comportamento documentado e o implementado. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Registre arquivo e linha, pré-condições, ativo afetado, fluxo de dados e efeito observável em fixture. Separe declaração de contrato, indício estático e falha reproduzida. Tente refutar a hipótese com chamadas legítimas, controles de acesso esperados e configuração efetiva. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Priorize controles no servidor, APIs seguras da linguagem, limites explícitos, privilégios mínimos, gestão central de segredos e bibliotecas suportadas. Explique o risco sem copiar dados sensíveis. A correção deve reduzir a causa e deixar evidência de auditoria apropriada. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Acrescente regressões para o comportamento permitido e negado, entradas limites e estados de erro. Use dados sintéticos e ambientes isolados; verifique também que logs e relatórios não reproduzam credenciais, tokens ou conteúdo privado. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Use uma lista de verificação adaptada ao impacto e à arquitetura, não como prova automática de segurança. Uma revisão estática não garante ausência de falhas; valide premissas, permissões de execução e configuração implantada. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
