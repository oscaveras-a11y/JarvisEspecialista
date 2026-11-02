# Prevenção de injeção de comandos

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

A opção mais segura é evitar interpretar texto por um shell. Se uma integração de processo for necessária, use API que recebe executável e argumentos separados, escolha executável fixo, limite opções e reduza privilégios.

## Como revisar

Procure montagem de linha de comando com entrada externa, chamadas de shell, executáveis localizados por PATH mutável, diretórios controláveis e permissões amplas. Analise se argumentos podem alterar o modo da ferramenta mesmo sem metacaracteres. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Trace os dados até a criação do processo e registre executável, argumentos estruturados, ambiente e usuário efetivo. Reproduza apenas em fixture local, com utilitário inofensivo que registra os argumentos recebidos. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Remova shell quando possível, use lista de argumentos, allowlist de opções e diretórios controlados. Defina timeout, ambiente mínimo, limites de saída e usuário sem privilégios. Não confie apenas em remover caracteres. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Teste espaços, aspas e valores iniciados por hífen como dados inofensivos. Confirme que não há interpretação de shell, que o processo tem timeout e que erros não expõem ambiente ou segredos. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Argumentos separados evitam uma classe de interpretação, mas ainda pode haver opção perigosa no programa chamado. Verifique a semântica do executável e prefira biblioteca nativa quando viável. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
