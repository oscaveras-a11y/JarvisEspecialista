# Inventário web automático

Este incremento torna web_inventory executável nas campanhas. Identifica referências e formulários no HTML recebido pelos GETs explicitamente autorizados. Não executa JavaScript, não usa navegador, não envia formulários e não segue links descobertos.

## Uso

O grant.json continua no formato de docs/web-probe.md: origem HTTPS e até8caminhos explícitos. Só esses caminhos recebem GET.

```text
cyber --home STORAGE web-probe CASE_ID EVIDENCE_DIRECTORY/grant.json --inventory
```

Ou use campaign.json com:
```json
{"version":1,"stages":["https_probe","web_inventory"],"web_grant":"grant.json","seconds":30,"body_bytes":65536}
```

```text
cyber --home STORAGE pentest create CASE_ID EVIDENCE_DIRECTORY/campaign.json
cyber --home STORAGE pentest run CASE_ID CAMPAIGN_ID
cyber --home STORAGE report CASE_ID
```

Cada etapa da campanha faz sua própria rodada autorizada; incluir https_probe e web_inventory significa duas etapas. Uma etapa já concluída não é repetida ao retomar a campanha. O receipt de inventário é separado do receipt de observação HTTPS.

## Dados e interpretação

Registra rotas somente se o caminho coincide com a lista explícita do grant. Query/fragmentos são removidos, referências fora do escopo contam apenas como números. Referências de ação dos formulários indicam método e caminho quando autorizado; uma ação POST é observada, nunca enviada.

Valores de campos, texto HTML, cookies e URLs externas não são persistidos. Os nomes dos campos são substituídos por SHA-256, mantendo tipos e contagens. Hash é identificador pseudônimo, não garantia de anonimização. O sinal csrf_related_name_observed significa apenas que apareceu um nome semelhante a CSRF/XSRF; não comprova proteção ou vulnerabilidade.

O primeiro base href é aplicado também a referências anteriores na página. Formulário sem action aponta para o documento, independentemente de base. Formulários aninhados, atributos duplicados e associações form=id não são tratados como DOM completo e tornam o resultado parcial.

## Limites e resultados parciais

Leitura incremental UTF-8, em blocos no processo HTTPS supervisionado; sem guardar uma cópia completa do corpo. Orçamento de corpo padrão64KiB, máximo1MiB, preservando timeout, TLS, DNS/pinning e autorização existentes.

Por resposta: até32referências brutas (máximo2048caracteres cada), até8rotas autorizadas,2formulários e8campos por formulário. Contagens de omissões e quality_flags explícitos. Nomes de campos acima128caracteres são omitidos. Esses limites mantêm a saída do worker dentro de64KiB para até8respostas.

Somente text/html com charset UTF-8/us-ascii ou ausente, sem codificação de conteúdo. Charset diferente e corpo comprimido são unsupported; não há descompressão automática. Corpo incompleto, UTF-8 inválido ou limites atingidos geram partial. Respostas nãoHTML são not_html, não falhas de segurança.

O parser cobre markup estático, não DOM renderizado, CSS, rotas criadas em JavaScript, controles associados a formulários por id, autenticação ou APIs. A campanha continua full_pentest_completed=false. Resultados não são vereditos de vulnerabilidade.

## Validação

Testes unitários usam HTML sintético, UTF-8 dividido byte a byte, queries/valores privados, base, limites e associações não suportadas. Integração Linux usa HTTPS real em servidor sintético do runner, com TLS/DNS/pinning/CORE, valida os formulários recebidos e a execução/retomada da etapa de campanha sem requisições extras.

Regressões Linux/Windows preservam a observação HTTPS e as campanhas anteriores. TLS de ponta a ponta desta fixture é validado no Linux. Nenhum site ou evidência real foi analisado. Desenvolvimento e testes seguem somente no GitHub.
