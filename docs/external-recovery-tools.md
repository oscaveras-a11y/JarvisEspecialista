# Integração das seis ferramentas externas

Autorização: o proprietário pediu integrar Hashcat, John Jumbo, QPDF, OpenSSL, Detect It Easy e Unblob da lista da sessão desktop. A dispensa de aprovações intermediárias permanece conforme AGENTS.md e continuation-plan.md. Execução de desenvolvimento/validação somente no GitHub. Base própria 8585d5a (PR23); não editar nem integrar branch Claude.

## Arquitetura
Extensão dos comandos e sessões existentes, com perfis de argv fechados e executáveis absolutos definidos pelo operador do ambiente remoto. Nada proveniente do arquivo vira comando ou opção. O subprocesso fixo recebe candidata por stdin; ferramentas nunca recebem senha em argv. Código não baixa dependências em runtime. Provisionamento separado em runner Linux.

DIE/Unblob: comando external-analyze CASE CAMINHO --tool die|unblob. Adquire cópia verificada, verifica autorização/pausa antes e depois, revalida o resultado e persiste metadados em operation_results já reconstruída pelo relatório. Conteúdo bruto de saída externa, caminhos internos e segredos não são persistidos. Unblob usa skip-extraction e profundidade 1: identifica contêineres sem extrair seus membros; recortes privados temporários podem ser criados e são removidos ao concluir, falhar ou cancelar.

Recuperação: novos modos em RecoverySessions, preservando HMAC da lista, auditoria, checkpoints, lease, pausa e cancelamento. Perfis iniciais: qpdf-pdf, openssl-pkcs12, hashcat-sha256, john-sha256, john-zip e hashcat-zip-aes. John zip2john trabalha sobre contêiner real e Hashcat mode13600 sobre ZIP WinZip AES; SHA256 exige digest hexadecimal explícito, sem supor que arquivo arbitrário seja hash de senha. OpenSSL valida PKCS12 com verificação de senha/estrutura; não infere parâmetros de enc a partir de Salted__. QPDF valida senha/estrutura do PDF. Modos confirmam candidata, sem exportar arquivo desbloqueado. Por solicitação expressa do proprietário, a senha confirmada pode ser exibida com recovery-session show --show-password, verificando a lista original por HMAC; consultas padrão, banco e relatórios não recebem uma cópia da senha. Ver docs/external-password-display.md. A descriptografia/exportação persistente é um contrato separado a validar, não sucesso presumido por código de saída.

## Controles
Somente Linux para CLIs externas nesta entrega. Dependência ausente é explicitamente indisponível; não retornar sucesso/resultado simulado. Sessões internas anteriores mantêm Windows/Linux. Até 8MiB por alvo, 64 bytes por candidata dos perfis John/Hashcat; até 1024 bytes para QPDF/OpenSSL. CR/LF/NUL recusados na tentativa externa. Cada chamada tem limite compartilhado de tempo, stdout/stderr combinados até 256KiB, limite de arquivo 16MiB e CPU finita no processo Linux. Não há promessa de limite rígido global de RAM ou uso de GPU.

Scratch exclusivo, privado, fora de Git e removido ao concluir, falhar ou cancelar. Potfile do John indispensável para confirmar match nunca é persistido, exposto em logs/relatórios ou reutilizado. Hashcat usa pot/log/restore desativados. Não encaminhar credenciais de provedores/GitHub às ferramentas. Ferramentas analisadas jamais são executadas como programa.

## Prova de entrega
Testes negativos antes do adaptador: indisponibilidade, autorização/pausa, alvo adulterado, saída excessiva/erro e status falso. Workflow separado instala as seis ferramentas reais no Ubuntu24.04, registra versões e executa amostras sintéticas. Testes de senha errada/correta e ZIP AES extraído por zip2john. DIE analisa ELF compilado mas não executado; Unblob identifica TAR sintético sem extração. Suíte completa e demo Linux/Windows; combinação fixada com candidato Claude somente no runner; revisão independente e PR próprio.

## Ferramentas e versões
Hashcat do Ubuntu noble + POCL CPU; John Jumbo commit5184bc0b8c105f8c5978b112e723d65b2de3e63e; DIE3.10 para Ubuntu24.04; Unblob26.6.4; QPDF/OpenSSL da distribuição com versões efetivas registradas. Dependências transitivas de apt/pip não são um lock integral. Cada executável usado é inventariado por SHA256; nenhum GPU ou hardware é presumido.

## Limites da cobertura
Integrar seis programas não implementa todos os formatos suportados por cada um. RAR, 7z/Office/PDF pelo Hashcat/John e OpenSSL enc genérico exigem perfis/conversores e vetores específicos futuros; as bibliotecas do PR23 continuam disponíveis para 7z/Office/PDF. Não há tentativa de autenticação de contas, rede ou programas remotos.
