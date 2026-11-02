# Autenticação e armazenamento de senhas

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Autenticação prova uma identidade em determinado contexto; autorização decide o que essa identidade pode fazer. Proteja credenciais no cadastro, armazenamento, recuperação, sessão e telemetria, sem coletar ou tentar descobrir senhas de pessoas.

## Como revisar

Verifique armazenamento reversível ou hash rápido, reset previsível, comparação que revele diferenças, sessão que não muda após login, ausência de proteção contra abuso e mensagens que enumerem contas. Confira suporte real a MFA e política de sessão. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Use contas e senhas sintéticas em ambiente de teste. Examine configuração e formato de hash sem divulgar valores. Teste fluxos de login, expiração, reset e bloqueios de forma limitada e autorizada, separando requisito declarado do comportamento observado. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Use biblioteca atual para hash de senha com salt individual e parâmetros adequados, gestão segura de sessão, MFA quando aplicável e recuperação de conta robusta. Implemente limitação proporcional, alertas e mensagens uniformes sem bloquear indevidamente usuários. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Teste criação, autenticação, troca e recuperação de credenciais sintéticas, expiração e revogação de sessões. Garanta que logs e respostas não contenham segredo e que os controles de taxa funcionem. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Políticas dependem do risco e da plataforma; não armazene listas de senhas reais nem faça credential stuffing. Algoritmos e parâmetros devem acompanhar orientação oficial vigente. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
