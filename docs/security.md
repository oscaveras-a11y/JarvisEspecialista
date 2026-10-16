# Limites e operação segura

Este protótipo serve a um operador local em arquivos próprios ou autorizados. Não é um serviço multiusuário, sandbox de malware ou produto forense certificado. Não executar arquivos suspeitos neste computador. Os analisadores só leem bytes e escrevem cópias e relatórios no armazenamento da investigação.

## Dados e clientes

Use CYBER_HOME separado por cliente, fora de repositórios Git, e acesso por conta Windows apropriada. O banco contém objetivos, caminhos, autorizações e resultados; logs são eventos estruturados no SQLite. SQLite não cifra dados nem implementa ACLs por linha. Configure NTFS ACLs e criptografia de disco conforme o ambiente antes de usar dados confidenciais. Nenhuma ACL ou criptografia é alegada como instalada automaticamente.

O perfil de autorização é local, com responsável declarado, justificativa, escopo, prazo e revogação. Não existe autenticação multiusuário ou assinatura do autorizador. Não ofereça este protótipo a clientes como se esses controles já existissem.

## Evidências

O original não é modificado. A aquisição cria arquivo exclusivo, calcula hash e verifica a cópia. Data UTC, origem, hash, tamanho e operações são auditados. Uma interrupção abrupta entre a escrita da cópia e o commit pode deixar cópia órfã; a retomada usa outro nome e não duplica resultados no banco. Limpeza automática desses órfãos não está implementada.

Validação rejeita UNC/device paths, ADS, traversal, symlinks e reparse points. Isso não elimina completamente corridas de troca de arquivos por outro processo privilegiado; para evidências profissionais, use mídia protegida contra escrita e aquisição forense adequada. Não escreva em diretórios de armazenamento compartilhados com programas não confiáveis.

Os eventos têm encadeamento SHA-256 transacional. Ele detecta edições parciais, mas alguém com escrita no banco pode reconstruir a cadeia ou truncá-la. Não é assinatura digital nem cadeia de custódia imutável. Use retenção externa assinada quando necessária.

## Segredos e agentes

Nenhuma chave, token ou plaintext é registrado nos eventos AES. Uma referência aleatória identifica cada material fornecido. Não guardar arquivos de chave na pasta de entrada analisada. O processo Python mantém a chave e o plaintext em memória; não oferece apagamento garantido de memória nem proteção contra administrador local.

Conteúdo de evidências não é encaminhado aos agentes. O adaptador recebe campos derivados e definidos pelo sistema. Respostas não são executadas automaticamente. O primeiro adaptador depende do sandbox read-only do Codex CLI; não constitui fronteira de segurança contra um CLI comprometido ou processos descendentes maliciosos. A execução deve ocorrer sob usuário restrito. Não usar o adaptador para execução autônoma de comandos em máquinas de clientes.

Limites de bytes, tentativas, duração e saída são aplicados. AES é limitado em tamanho, mas uma chamada criptográfica nativa não é preemptada no meio; o prazo é conferido antes/depois e a saída é descartada se excedido. Limite rígido de memória/processos via Windows Job Objects, teto de custo monetário e worker gerenciado ficam para a Fase 5.

## Publicação

Somente fonte, configuração pública, testes geradores e documentação devem ir para GitHub privado. Banco, cópias, arquivos recuperados, credenciais e relatórios de clientes ficam fora do checkout. O teste sintético não autoriza qualquer investigação de terceiros.
