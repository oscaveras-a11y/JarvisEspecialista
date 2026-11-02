# Prevenção de XSS

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Cross-site scripting é prevenido principalmente tratando dados como dados no contexto de saída. O escape correto varia entre texto HTML, atributo, URL, JavaScript e CSS; um escape genérico ou validação de entrada não cobre todos os contextos.

## Como revisar

Localize renderização HTML direta, APIs que interpretam markup, templates sem escape, atributos URL não validados e conteúdo salvo exibido a outros usuários. Revise também CSP como camada adicional, sem tratá-la como substituta do escape contextual. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Siga entrada sintética até a saída renderizada e observe se é texto ou markup. Faça testes em ambiente local, com conteúdo inofensivo que permita inspecionar a codificação, sem executar scripts ou atingir usuário real. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Prefira APIs que inserem texto, templates com escape automático e sanitizador reconhecido quando HTML limitado for requisito. Valide esquemas de URL, aplique CSP restritiva e evite misturar código e dados. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Cubra contextos de texto, atributo e URL com valores de teste não executáveis; verifique DOM resultante e cabeçalhos. Teste também conteúdo armazenado e refletido com contas sintéticas. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

A presença de CSP ou de um framework não garante segurança se houver escape explícito inseguro. O resultado depende do contexto e da versão; valide a saída real. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
