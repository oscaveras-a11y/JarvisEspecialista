# Dependências e cadeia de suprimentos

Esta referência serve à revisão e à correção de software próprio ou explicitamente autorizado. Ela não contém alvos, credenciais, instruções de exploração ou automação ofensiva. Use fixtures inventadas, ambiente isolado e autorização verificável; interrompa a atividade se o escopo não estiver claro.

## Objetivo

Dependências herdam o alcance do processo que as carrega e podem trazer vulnerabilidades, mudanças inesperadas ou risco de distribuição. Avalie origem, manutenção, versões, integridade e necessidade, não apenas o número bruto de alertas.

## Como revisar

Procure dependências abandonadas, versões flutuantes, lockfile ausente, scripts de instalação, fontes não verificadas, permissões de CI excessivas e componentes transitivos desconhecidos. Faça o percurso de ponta a ponta e registre premissas, fronteiras e controles existentes. Confirme o comportamento no código e na configuração, não apenas no nome da função ou no contrato.

## Evidências

Gere inventário ou SBOM em ambiente reprodutível, compare lockfile e manifesto, consulte advisories oficiais e determine se versão afetada e função vulnerável estão presentes. Registre versão e data da consulta. Preserve apenas o necessário para reproduzir a conclusão: versão, local do código, condição, resultado e hash quando útil. Redija segredos e dados pessoais, mantendo evidência privada em local aprovado.

## Correção

Atualize para versão corrigida compatível, remova componentes não usados, fixe versões e verifique integridade com mecanismos do ecossistema. Restrinja tokens e permissões de build; mantenha processo de exceção com prazo e dono. Prefira uma mudança pequena na causa raiz, com defesa em profundidade e privilégio mínimo. Explique impacto, compatibilidade e qualquer risco residual; evite esconder falhas por mensagens ou filtros superficiais.

## Teste de regressão

Execute auditoria em CI, testes de regressão e build limpo a partir do lockfile. Verifique compatibilidade Windows/Linux e confirme que alertas resolvidos não reaparecem. Compare caso permitido e caso negado, limites e erro. Use dados sintéticos determinísticos, não dependa de rede pública e confirme que a correção não desabilita funcionalidade legítima.

## Limites

Um alerta de CVE não prova explorabilidade no produto, e ausência de alerta não prova cadeia segura. Confirme alcance, configuração, exposição e correção disponível. Trate resultado como válido apenas para escopo, versão e configuração observados. Falta de alerta não comprova ausência de risco; uma declaração do sistema também não comprova sua imposição.

## Fontes

- https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/

Revise as fontes oficiais no momento da implementação: versões, defaults e recomendações podem mudar. Esta nota é material de referência local, não certificação nem substituto de revisão humana.
