# Exibir a senha recuperada

A consulta explícita está disponível para uma sessão de recuperação concluída com sucesso:

```text
cyber recovery-session show CASE SESSION --show-password
```

Sem a opção, show, list, relatórios e resultados persistidos continuam sem senha.
Com a opção, o JSON inclui password e password_encoding (utf-8 ou hex para bytes
que não representam UTF-8). O terminal recebe a senha; execute esta consulta
somente no ambiente remoto autorizado, fora de logs públicos de CI.

A senha é recuperada da linha vencedora da lista original de candidatas. Não é
criado um segundo arquivo de senhas. A operação exige autorização de recuperação
ativa, caso não pausado, sessão bem-sucedida, auditoria e checkpoint íntegros,
evidência verificada e HMAC da lista original. Lista alterada ou removida impede
a exibição. Uma chave CCAES1 não é apresentada como senha.

O evento de auditoria registra somente o identificador da sessão. A exibição não
desbloqueia nem exporta arquivos. O beta continua sem login adicional da aplicação,
conforme decisão do proprietário; esta opção não implementa autenticação de usuário.

## Ferramentas externas

```text
cyber external-tools
cyber external-analyze CASE PATH --tool die
cyber external-analyze CASE PATH --tool unblob
cyber recovery-session start CASE PATH --candidates LIST --mode qpdf-pdf
```

Perfis: qpdf-pdf, openssl-pkcs12, hashcat-sha256, john-sha256, john-zip,
hashcat-zip-aes. Exigem Linux e executáveis absolutos configurados no ambiente
remoto. Cada resultado confirmado inclui versão e SHA-256 do executável.
ZIP usa conversor zip2john e registra seu SHA-256. Resultado da ferramenta precisa
concordar com a validação independente; um status de sucesso sozinho não basta.

DIE e Unblob identificam cópias verificadas. Unblob usa skip-extraction e profundidade
1: pode criar recortes privados temporários, removidos ao terminar; não extrai
membros de arquivos nem publica os recortes. Metadados persistidos não incluem
saída bruta, caminho interno ou nome de arquivo do relatório da ferramenta.

CLIs externas têm cobertura Linux; formatos internos preservam Windows/Linux.
OpenSSL enc/AES-CBC e exportação de arquivos desbloqueados ficam fora desta entrega.
