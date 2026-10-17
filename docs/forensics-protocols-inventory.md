# Inventário estático de disco e PCAP — incremento isolado

Base: `4ca8b44b5250c760302137e3033ddcc7f571214c`. Esta entrega acrescenta leitores limitados; não conclui perícia digital nem protocolos profissionais. Nenhum módulo está conectado automaticamente à CLI, ao serviço ou ao processo supervisionado do CORE.

## Contrato para integração posterior

- `cyber_core.forensics.disk.inspect_disk_image(data: bytes, *, sector_size=512, max_bytes=16777216, max_partitions=256) -> dict`.
- `cyber_core.protocols_pcap.inspect_pcap(data: bytes, *, max_bytes=16777216, max_packets=256) -> dict`.

Ambas exigem bytes imutáveis e devolvem estruturas JSON sem bytes brutos. O chamador deve obter os bytes de uma cópia autorizada/verificada, aplicar seu limite antes de ler, conferir o hash esperado e registrar custódia. O SHA-256 retornado identifica exatamente os bytes recebidos; não prova origem, aquisição forense, autorização ou integridade anterior à chamada. As funções não abrem caminhos, dispositivos ou rede.

O teto de entrada é 64 MiB; orçamento padrão de 16 MiB. Disco aceita setores declarados de 512 ou 4096 bytes e imagem com setores completos. Há teto de 1024 entradas de partição, 256 registros exportados de sobreposição e 4096 pacotes. Orçamentos inválidos e estruturas inválidas lançam `ValueError`. Exceder `max_bytes` recusa a entrada inteira. O limite de pacotes retorna progresso parcial e `next_record_offset`; não deve ser apresentado como captura inteira analisada.

Offsets são bytes a partir de zero; intervalos são `[offset, offset + length)`. Resultados de sucesso incluem `schema_version=1`, tamanho e hash. O processo supervisionado, cancelamento, auditoria, autorização, caminhos e classificação de conteúdo continuam responsabilidades da integração posterior. Não chamar diretamente estas funções no serviço como substituto do processo monitorado.

## Disco

MBR: quatro entradas primárias, intervalos contra tamanho da imagem e interseções entre partições e metadados. Contêineres estendidos são identificados, sem caminhar EBR. Não há identificação de sistema de arquivos nem inferência de arquivos apagados.

GPT: cabeçalho primário, revisão 1.0, CRC32 do cabeçalho com o campo CRC zerado e CRC32 da matriz inteira. Tamanhos, LBA e limites da matriz e partições são verificados antes das leituras. Sobreposições válidas em bounds são observações explícitas, nunca corrigidas. As entradas MBR são mantidas separadas para não confundir o contêiner protetor com uma partição GPT. MBR híbrido é declarado.

`backup_validated=false` sempre: não há validação, comparação ou reparo do GPT de backup. CRC válido não significa GPT integralmente válido, imagem autêntica ou sistema de arquivos íntegro. Nomes de partição não são exportados.

## Captura

PCAP clássico 2.4: quatro magics, endian registrado, timestamps inteiros com precisão original micro/nanosegundo, offsets de registro/dados e comprimentos. Somente linktype Ethernet sem flags adicionais; outros tipos e PCAPNG são recusados explicitamente. Reservados históricos do cabeçalho são ignorados conforme libpcap.

Ethernet, IPv4, TCP e UDP expõem metadados. IPv4 fragmentado não expõe transporte; não há remontagem. Cabeçalhos/comprimentos inválidos geram diagnósticos sem leitura fora dos limites. Cauda de registro truncada é relatada; não é decodificada como pacote completo. Captura reduzida por snaplen é distinguida de arquivo fisicamente truncado.

Não exporta payload, hex de payload, nomes DNS, conteúdo HTTP, TLS, credenciais ou fluxos. Endereços MAC/IP e portas são metadados potencialmente sensíveis: o chamador ainda controla seu acesso. Sem validação de checksums Ethernet/IP/TCP/UDP, FCS, VLAN, IPv6, PCAPNG, normalização de relógio ou interpretação de aplicação. Timestamps são declarações da captura.

## Validação e recibos

Somente GitHub Actions, Ubuntu/Windows e arquivos sintéticos. O workflow novo usa biblioteca padrão e não instala o produto ou provedores. O workflow geral existente continua independente.

Testes foram publicados antes da implementação: commit `73d07f8d116695436b58f951de26eb4586e4443c`, [execução 39041073575](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39041073575), falha esperada nos dois sistemas por ausência de `cyber_core.forensics` (log Ubuntu job `117420521086`). Resultados posteriores devem ser conferidos no [PR draft 15](https://github.com/oscaveras-a11y/JarvisEspecialista/pull/15); execução pendente não é aprovação. Nenhum teste foi executado no computador do proprietário.

A suíte cobre limites, offsets MBR/GPT em setores 512/4096, CRC inválido, sobreposição, timestamps, endian, truncamento, fragmentos IPv4 e comprimentos TCP/UDP. Passar esses cenários não prova prontidão profissional, suporte a formatos além dos declarados ou integração CORE.

## Fontes primárias consultadas em 2026-10-17

- [UEFI 2.11, capítulo 5, MBR e GPT](https://uefi.org/specs/UEFI/2.11/05_GUID_Partition_Table_Format.html).
- [libpcap, documentação oficial do savefile](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in).
- [RFC 791, IPv4 e fragmentação](https://www.rfc-editor.org/rfc/rfc791).
- [RFC 9293, TCP](https://www.rfc-editor.org/rfc/rfc9293).
- [RFC 768, UDP](https://www.rfc-editor.org/rfc/rfc768).

São referências de layout; este inventário deliberadamente não implementa toda a semântica desses padrões.
