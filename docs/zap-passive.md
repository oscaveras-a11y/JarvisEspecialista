# ZAP passivo no CORE

Comando: cyber --home STORAGE web-passive CASE grant.json --ca-file ca.pem --seconds 180.
Campanha: {"version":1,"stages":["dast_passive"],"web_grant":"grant.json","seconds":180}.
Grant segue docs/web-probe.md. CA opcional pública; verificação TLS permanece obrigatória.

O transporte existente coleta somente GETs de até oito caminhos explícitos, com DNS público/pinning/TLS, sem redirects, cookies enviados, proxies ou crawling. Copia respostas limitadas em HAR temporário. ZAP importa com sendRequests=false, em contêiner Linux network=none sem socket Docker montado. Não há interceptação TLS: metadados TLS são do transporte upstream; o scanner analisa apenas mensagens importadas.

Imagem ZAP2.17.0: ghcr.io/zaproxy/zaproxy@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238.
Docker local Linux e imagem já disponível são pré-requisitos; o adaptador não baixa imagens. Ausência produz unavailable/unsupported_automation. O workflow instala o backend no runner descartável; nada é instalado no computador do proprietário.

Mesmo prazo compartilhado até300s, limitado pelo CORE, cobre preflight, coleta, startup e fila passiva. Aquisições CORE anteriores têm orçamento próprio. Scanner: rede nenhuma, rootfs somente leitura, sem capabilities, no-new-privileges, CPU1,1GiB memória/swap,128PIDs,tmpfs512MiB. Java heap512MiB não equivale à memória total. HAR temporário até16MiB; até128 alertas antes de deduplicação. Importação, quantidade de mensagens, fila completa, versão e add-ons são verificados.

Corpos, cookies e headers completos permanecem somente no scratch temporário e na sessão temporária do scanner. Nenhum conteúdo bruto é impresso/exportado pelo driver. Resultados guardam regra, risco, confiança, GET/caminho autorizado e classification=suspected. Cookies guardam contagens/atributos, sem nomes ou valores. Não é cofre criptografado; término abrupto do host pode deixar scratch órfão. Contêiner tem watchdog próprio; o CORE também remove seu nome exclusivo ao sair.

Alertas não viram automaticamente vulnerabilidades validadas. completed significa coleta e processamento passivo previstos concluídos, não site seguro. Truncamento, encoding não suportado, redirects, descarte de alertas e falhas de coleta tornam cobertura partial. Não há exploração, login, SAST/SCA nem pentest completo. full_pentest_completed permanece false.

Pausa, revogação, validade e hashes dos insumos são conferidos na supervisão e dentro da transação de publicação. Campanha usa receipt auditado: operação publicada é adotada após falha no checkpoint sem repetir HTTP. Sem receipt, GETs podem repetir; não há checkpoint por requisição.

## Validação
Workflow Scoped passive ZAP: contratos Windows/Linux, integração ZAP real com HTTPS sintético no Linux e suíte completa. Windows não comprova backend ZAP real. Somente entradas inventadas; nenhum site real, segredo real ou evidência de cliente.
RED inicial: https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/41145546060.
Resultados finais serão registrados após execução.
