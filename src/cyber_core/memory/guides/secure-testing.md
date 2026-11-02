# Testes seguros e regressão

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Testes de segurança devem provar propriedades específicas em ambientes autorizados e isolados. Combine revisão, análise estática, testes unitários, integração e validação de configuração; cada método tem cobertura e falsos positivos diferentes.

## Como revisar

Procure dependência de testes manuais não repetíveis, fixtures com dados reais, caminhos sem casos negados, scanner sem triagem e CI com credenciais ou permissões desnecessárias. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Formule hipótese, pré-condições, critério de sucesso e evidência mínima. Use fixture sintética reproduzível, registre versão e ambiente e classifique resultado como declaração, alerta ou falha confirmada. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Converta falhas confirmadas em regressões que falham antes da correção e passam depois. Use serviços descartáveis, dados inventados, permissões mínimas e redija saída. Corrija a causa e documente risco residual. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Execute checks no CI em plataformas relevantes, mantenha testes determinísticos e monitore flakiness. Verifique também cancelamento, retomada, limpeza e ausência de efeitos fora da fixture. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Um conjunto finito de testes não prova segurança geral. Resultado negativo vale para o escopo e configuração testados; registre limitações e necessidade de revisão adicional. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Software_Security_Testing_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
