# Verificação HTTPS em alvo autorizado

O comando web-probe aceita origens HTTPS reais e até oito caminhos explicitamente autorizados. Realiza GET, valida o certificado e registra observações de protocolo. O antigo web-lab permanece restrito ao laboratório que demonstra escrita/restauração.

## Escopo do teste

Verifica conexão TLS, certificado sob raízes selecionadas, status HTTP, presença de cabeçalhos de segurança e SHA-256 do corpo recebido ou de seu prefixo. Não tenta invasão, autenticação, exploração, modificação, força bruta, execução de JavaScript ou descoberta de caminhos. Cabeçalhos ausentes são observações de configuração; nenhum resultado declara o site seguro ou vulnerável por si só.

## Preparação

Python e instalação habitual do projeto; nenhuma ferramenta externa adicional em produção. Operação real fica a cargo do proprietário no ambiente autorizado futuro. Desenvolvimento e validação atuais seguem somente no GitHub, sem operar sites reais nem publicar evidências privadas.

Crie um arquivo local grant.json dentro do diretório de evidências da investigação. Exemplo com domínio ilustrativo, que deve ser substituído pelo domínio autorizado:
```json
{
  "version": 1,
  "origin": "https://seu-dominio.example",
  "paths": ["/", "/pagina-autorizada"],
  "allow_read": true,
  "authorization": "Sou responsável pelo site e autorizo estas leituras",
  "expires_at": "2026-10-29T18:00:00-03:00"
}
```

Ajuste a validade para um horário futuro real. A declaração não verifica identidade/propriedade, nem substitui autorização do responsável pelo alvo. Uma oferta de recompensa ou o caráter público de um órgão não concede autorização de teste.

Registre a investigação e execute:
```text
cyber --home STORAGE investigate --project web --objective "Verificação HTTPS" --scope EVIDENCE_DIRECTORY --owner RESPONSAVEL --authorization "Teste autorizado do meu site"
cyber --home STORAGE web-probe CASE_ID EVIDENCE_DIRECTORY/grant.json --seconds 30 --body-bytes 65536
cyber --home STORAGE report CASE_ID
```

Opcionalmente forneça --ca-file EVIDENCE_DIRECTORY/ca.pem para um certificado público de CA até4096 bytes adquirido/verificado pelo CORE. Não forneça chaves privadas. A CA fornecida é adicionada às raízes do sistema e tem hash registrado. Não há opção de desativar verificação TLS. Sem CA extra usa as raízes padrão do Python/OpenSSL da plataforma.

## Controles

Somente HTTPS, sem credenciais, query, fragmentos ou caminhos fora da lista. Origem não admite caminhos adicionais. Caminhos ASCII até256 caracteres, sem percent-encoding, segmentos . ou .. ou //; não há wildcards, crawling nem redirects. Portas443 ou1024..65535.

DNS resolve no processo supervisionado. Todos os endereços devem ser públicos; resposta mista pública/privada é rejeitada. Conecta diretamente a um IP validado, preservando hostname no TLS e Host HTTP. Não usa proxies do ambiente. IPv6 limitado a unicast2000::/3, sem6to4/Teredo; NAT64 e redes privadas/locais/multicast são rejeitadas.

Limites: manifesto8192 bytes; até8 GETs; intervalo mínimo0,25s; até1MiB de corpo por resposta (padrão64KiB), leitura em blocos. Pode ler um byte adicional para determinar truncamento, sem incluí-lo no hash. Hash de prefixo sempre recebe body_complete=false e hash_scope=response_body_prefix. Não descomprime conteúdo nem interpreta HTML. Cabeçalhos são limitados pelo parser padrão Python (até100 linhas de64KiB) e rejeitados se o total interpretado exceder64KiB.

Prazo total do processo até300s (padrão30), limitado pelo CORE, com encerramento da árvore se DNS/TLS/leitura bloquear ou a investigação for pausada/revogada/cancelada. Timeout de socket até5s. Manifesto/CA são conferidos durante supervisão; mudanças ou expiração interrompem a operação. Revogação não é transação atômica com servidor remoto: um GET já enviado não pode ser desfeito. GETs também podem ter efeitos mal implementados no servidor; use caminhos apropriados.

Corpos, cookies, cabeçalhos brutos e erros remotos não são persistidos nem impressos. São registrados apenas status, presença dos cabeçalhos selecionados, IP público, metadados TLS, hashes e contagens. O resultado é salvo com hashes dos insumos, parâmetros, versões Python/OpenSSL e auditoria existente.

## Resultado e pendências

completed significa que as observações previstas terminaram, não que o site está seguro. Falha de certificado/conexão, redirect ou corpo truncado produz partial, com causa explícita. Interrupções externas registram web_probe_interrupted quando o CORE consegue gravar; encerramento abrupto do processo principal pode impedir esse registro. Não há checkpoint por requisição; repetir cria nova operação.

Este incremento não acrescenta um motor completo de pentest nem verifica firmware/eleições através de uma URL. Logs de servidor e medições de firmware continuam exigindo coleta autorizada e análise de arquivos.

## Evidência de testes

Workflow web-https-probe.yml: servidor HTTPS sintético com certificado gerado temporariamente, hostname reservado .test, IP público roteado para loopback no runner. Exercita o MESMO filtro público/pinning/TLS usado em produção, sem exceção para endereços privados no programa. TestaCLI→CORE→processo→HTTPS→auditoria/relatório, validação positiva e negativa de certificado, redirects e limite de corpo. Nenhum site real foi analisado.

```text
python scripts/run-tests.py test_web_probe.py
python scripts/run-tests.py
```
