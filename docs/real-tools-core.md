# Ferramentas reais no CORE — beta

Ghidra 12.1.4 e Binwalk 3.1.0 podem ser habilitados explicitamente em
analyze-firmware. A execução usa a cópia verificada, no filho monitorado
do CORE; os resultados ficam no SQLite e no relatório da investigação.

## Testar somente no GitHub

Após integração na main, abra Actions → Real external backends → Run workflow.
O cenário é sintético e fixo: compila um ELF sem executá-lo, interpreta um PE
conhecido com Ghidra e localiza gzip conhecido com Binwalk. O resultado final
exige core_sqlite_report=true e binwalk_cli=true; ausência de ferramenta,
falha de download ou análise incompleta não vira aprovação.

As ferramentas são instaladas no runner descartável Linux, com hashes
verificados. Nada é instalado no computador do proprietário. O GitHub pode
ser acompanhado pelo navegador tanto em Windows quanto em Linux.
O CORE e a ausência das dependências opcionais também têm testes Windows;
esta entrega não declara os executáveis nativos dos backends validados no Windows.

## Configuração no ambiente de execução

A API preserva o construtor existente:

    core.configure_external_tools({
        "ghidra": {"home": "/trusted/ghidra_12.1.4_PUBLIC", "java_home": "/trusted/jdk"},
        "binwalk": {"executable": "/trusted/binwalk/bin/binwalk"}
    })

Os caminhos são configuração confiável do operador; não são obtidos de uma
amostra ou resposta de agente. A CLI aceita --ghidra-home, --java-home e
--binwalk-executable antes do comando analyze-firmware ou worker.
Ghidra exige os dois caminhos juntos. Configuração ausente mantém o fluxo
estático sem iniciar ferramentas. Resultados de dependência ausente,
plataforma/formato incompatível, análise parcial e falha são explícitos.

Ghidra interpreta somente ELF/PE reconhecidos, sem carregar bibliotecas nem
aplicar relocação ELF, e exporta até oito funções. Pseudocódigo não é o
código-fonte original nem prova de comportamento. Binwalk executa sem extração
e sem recursão, com até128 findings apresentados. Alguns parsers de assinatura
fazem descompressão interna para validar estruturas.

Na comparação de firmware, os backends são chamados uma vez, sobre a entrada
primária. Não há análise externa duplicada dentro do comparador.

## Limites e evidência

Preserva prazo compartilhado, limites de bytes e encerramento da árvore de
processos. A supervisão não é sandbox de privilégios/rede. O adaptador limita
stdio/JSON e monitora scratch; o teto agregado de disco pode ser excedido
entre verificações. Não há limite total de RAM nativa; o heap Java não equivale
à memória total. Não executa o binário analisado.

O ensaio [39062312922](https://github.com/oscaveras-a11y/JarvisEspecialista/actions/runs/39062312922)
comprovou a conexão sobre o candidato9928fd17a73d973ed5ac01915c2ae0c547c4c9ea:
Ghidra interpretou ELF/PE com constante42; Binwalk detectou gzip no offset256;
cópia verificada, persistência, relatório e CLI foram exigidos.
A adaptação deste PR preserva as interfaces da main e tem validação própria
em seus checks. Não confundir esse recibo anterior com aprovação de um head novo.

As credenciais dos provedores de IA não são necessárias para esses ensaios.
Nenhuma evidência de cliente, chave ou senha real deve ir para Git, logs
ou artefatos de teste.
