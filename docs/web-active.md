# Verificação web ativa com escopo explícito

Os comandos web-active, web-session-check e web-access usam a mesma autorização de investigação, auditoria, prazo e gateway HTTPS. Somente Linux com socket Unix é suportado; o scanner ativo também exige Docker e a imagem ZAP fixada. Ausência do backend retorna indisponível.

Exemplos após criar uma investigação:
```
cyber web-active CASE active.json --seconds 180
cyber web-active CASE active.json --retest-of OPERATION
cyber web-session-check CASE active.json --session-material private.json --profile alice
cyber web-access CASE active.json matrix.json --session-material private.json
cyber pentest run CASE CAMPAIGN --session-material private.json
cyber pentest resume-active CASE CAMPAIGN --reason "Revisei os efeitos e autorizo nova tentativa"
```

O manifesto ativo JSON versão 1 exige origin HTTPS pública, allow_active=true, authorization, expires_at com fuso, classes limitadas a reflected_xss e sql_injection e até oito routes. Cada rota declara path exato, methods, query_params e body_params; purpose é scan, login, check ou access. Não há curingas, crawling ou redirecionamento seguido. A leitura passiva continua usando seu manifesto separado.

ZAP executa sem rede, somente regras 40012 e 40018 selecionadas, sem spider. Uma origem HTTP virtual local encaminha pedidos por socket Unix ao gateway no host; só o host resolve e verifica TLS da origem HTTPS real. O frontend virtual não valida comportamento exclusivo de navegador, origem ou TLS do alvo. Alertas são suspeitas, não exploração confirmada.

O gateway limita a 128 tentativas, uma por vez, intervalo de pelo menos 0,5 segundo e prazo de até 300 segundos, reduzido pelo CORE. Resposta limitada a 1 MiB, cabeçalhos e enquadramento também limitados. Rejeições e interrupções mantêm cobertura parcial. Nenhum payload, cookie, senha ou corpo de resposta é salvo pelo scanner.

O arquivo privado de perfis é lido pelo broker no host e não é montado no container nem adquirido como evidência. Versão 1 tem profiles nomeados com kind anonymous, bearer, cookie, form ou json. Perfis autenticados exigem check com path e status, mais json_marker (field/value) ou critério explícito aceito pelo broker. Login form/json declara login.path e login.fields. Uma sessão é verificada antes de cada emissão autenticada; falha bloqueia o uso das credenciais. Cookies exigem Secure, escopo de caminho e expiração quando aplicável. OAuth/MFA arbitrário não é automatizado.

A matriz de acesso tem version=1 e cases: cada caso declara path, allowed, profiles, status e json_marker. Um controle positivo do recurso é obrigatório antes de avaliar os demais perfis. Marcadores e material privado não aparecem nos resultados.

Campanhas guardam recibos auditados. Uma interrupção ativa sem recibo deixa a etapa bloqueada; não há repetição automática com efeitos desconhecidos. resume-active exige decisão explícita do operador e preserva o histórico. Retestes criam operações novas e comparam regras observadas; desaparecimento de alerta não comprova correção.

Testes reais usam somente sites HTTPS descartáveis do GitHub Actions. Resultado sintético não equivale a um pentest profissional completo. Veja também security-coverage.md para a lista ampliada solicitada.
