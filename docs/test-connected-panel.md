# Testar o painel conectado no GitHub

## Abrir
1. No repositório, abra **Code → Codespaces → Create codespace on main** (ou [criar um ambiente](https://codespaces.new/oscaveras-a11y/JarvisEspecialista?ref=main)).
2. Aguarde a preparação remota. Python, Java, Ghidra e Binwalk são instalados no GitHub; a primeira preparação pode levar vários minutos.
3. Em **PORTS**, mantenha **8765 / CYBER CORE** como **Private** e clique no ícone **Open in Browser**. O painel deve mostrar **Motor conectado**.

A abertura do Codespace é uma ação do proprietário. Esse ambiente não foi criado pelos agentes. Usa tempo e armazenamento da franquia Codespaces da conta; consulte [franquia e cobrança do GitHub](https://docs.github.com/en/billing/concepts/product-billing/github-codespaces). Ao terminar, pare o ambiente em [Seus Codespaces](https://github.com/codespaces). Excluir o Codespace também exclui os dados guardados nele: baixe antes os relatórios necessários.

## Primeiro teste
1. Clique em **Nova investigação** e declare projeto, objetivo, responsável e autorização.
2. Selecione **Tarefas e progresso**. Escolha **Análise estática de arquivo** e um arquivo de teste autorizado de até **4 MiB**.
3. Clique em **Enviar e analisar**. O motor recebe o arquivo no Codespace, preserva uma cópia e calcula o SHA-256.
4. Veja **Resultados do CORE** e seus detalhes. Em **Relatórios**, clique em **Gerar e baixar relatório**.
5. Teste pausa, retomada e cancelamento na lista de investigações. Pausa bloqueia o próximo trabalho; cancelamento impede resultados tardios e exige nova investigação para continuar.

Arquivos desconhecidos são analisados estaticamente, nunca executados como programas. O resultado é uma observação; não constitui garantia de segurança nem resolução automaticamente comprovada.

## O que está conectado
- Criação persistente de investigações e uploads em escopo criado pelo servidor.
- Análise estática, firmware com Ghidra/Binwalk quando configurados, avaliação das opções de recuperação e inventários limitados de disco/PCAP.
- Fila, pausa, retomada, cancelamento, auditoria verificada, resultados e relatório técnico do CORE.
- Retomada de tarefas pendentes pelo botão correspondente. Um trabalho por vez neste beta.

Sessões de tentativa de chaves e chamadas reais aos agentes continuam fora deste fluxo visual. A análise de recuperação não promete descriptografar um arquivo sem a chave correta. Não são solicitadas chaves de provedor neste painel.

## Privacidade e armazenamento
A aplicação não cria outro login. O acesso usa a autenticação da conta GitHub à **porta privada** do Codespace, conforme [a documentação](https://docs.github.com/en/codespaces/reference/security-in-github-codespaces). Não mude a porta para Public nem compartilhe o ambiente. O servidor da aplicação não fornece autenticação própria ou isolamento profissional de múltiplos usuários.

Uploads, cópias e SQLite ficam em **~/.cyber-core-beta**, fora do checkout e do Git. Nenhum upload é enviado a provedores, colocado em commit ou publicado em Pages pelo aplicativo. O navegador mantém somente a apresentação; dados demonstrativos anteriores não são importados para investigações reais.

O serviço escuta somente loopback no ambiente remoto. O Codespaces encaminha a porta privada. A configuração do ambiente, nonce de requisição e verificações de origem não substituem a privacidade da porta.

## Conexão interrompida
Se o motor estiver indisponível, o painel conectado bloqueia as ações e informa a interrupção. Ele não troca por exemplos locais. Reabra o Codespace e atualize a página. Se necessário, no terminal do próprio Codespace execute **bash .devcontainer/start.sh**.

GitHub Pages continua sendo somente a demonstração estática. Para analisar um arquivo, abra o painel servido dentro do Codespace e confirme **Motor conectado**.

## Validação
Os testes HTTP e de navegador usam arquivos sintéticos nos runners GitHub Windows/Linux. A etapa Linux de ferramentas instala as mesmas versões/checksums do ambiente e exige descompilação da constante conhecida 42 no Ghidra e identificação de gzip no offset 256 pelo Binwalk, por chamadas HTTP ao CORE. A execução integral de um Codespace do proprietário deve ser confirmada após a abertura, sem confundi-la com esses testes do CI.
