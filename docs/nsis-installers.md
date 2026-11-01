# Extração NSIS estática — etapa VisionFT

O comando usa 7-Zip como ferramenta confiável e nunca executa o instalador ou os arquivos extraídos. Implementação inicial do backend: Linux com Python 3.12 de 64 bits. O restante do CORE mantém suas regressões Windows/Linux.

## Preparação no runner descartável

```sh
sudo apt-get update -qq
sudo apt-get install -y nsis p7zip-full
python -m pip install ".[reverse]"
python scripts/run-tests.py test_installers.py
python scripts/run-tests.py
```

NSIS/makensis só gera a fixture sintética de teste; não é necessário para inspecionar um instalador recebido. O 7-Zip real lista e extrai a fixture com compressão sólida. Nenhum VisionFT proprietário é usado pelo CI e nenhum arquivo extraído é publicado como artefato.

## Uso futuro em ambiente operacional privado

Registrar previamente o caso com escopo/autorização vigentes pelo fluxo existente. Opções globais precedem o comando:

```text
cyber --home DIRETORIO_OPERACIONAL --max-bytes 1073741824 --timeout 300 installer ID_DO_CASO CAMINHO_ABSOLUTO_DO_INSTALADOR --seven-zip /usr/bin/7z
cyber --home DIRETORIO_OPERACIONAL --max-bytes 1073741824 --timeout 300 installer ID_DO_CASO CAMINHO_ABSOLUTO_DO_INSTALADOR --seven-zip /usr/bin/7z --extract --max-extracted-bytes 1073741824 --memory-bytes 536870912
```

A primeira operação lista. A segunda extrai apenas VisionFT.exe e arquivos diretamente em Firmwares/ com extensão .vftw. Não extrai automaticamente outros membros. O destino é criado pelo CORE, fora do repositório, sem sobrescrever originais.

API: cyber_core.installers.inspect_installer(core, case, path, seven_zip=absolute_path, extract=False, max_extracted_bytes=1073741824, max_entries=1000, memory_bytes=536870912).

## Controles e evidências

- Aquisição em chunks e cópia verificada pelo CORE; SHA-256 da entrada conferido antes e depois da operação.
- Listagem exige identificação NSIS; entradas, tamanhos conhecidos, nomes duplicados sem distinção de caixa, links e caminhos perigosos são validados.
- Saída binária de cada seleção passa por stdout para arquivo criado pelo programa. Nomes do instalador nunca se tornam opções ou caminhos de escrita do 7-Zip; wildcard matching é desabilitado.
- Limite total de extração configurável até 2 GiB. Leitura/gravação limitada em chunks; tamanho real é contado inclusive quando a listagem não declara tamanho.
- Em NSIS sólido, alguns tamanhos podem estar ausentes. São registrados como null, com listing_sizes_partial=true; não são interpretados como zero. Tamanhos declarados são comparados aos extraídos.
- Cada resultado registra origem (hash do instalador e caminho interno), tamanho real, tamanho declarado disponível, SHA-256, versão e hash da ferramenta, parâmetros, arquivos produzidos e auditoria.
- O orçamento de endereço virtual do processo 7-Zip é configurável entre 128 MiB e 2 GiB (padrão 512 MiB), via RLIMIT_AS no Linux. Não representa teto agregado de RAM de toda a árvore.
- Prazo e cancelamento/revogação/pausa são supervisionados pelo CORE. Scratch tem monitor de até 2 GiB/3000 entradas; monitoramento tem overshoot possível, não quota rígida de filesystem. stderr é limitado a 64 KiB; listagem a 512 KiB; resposta a aproximadamente 1 MiB.
- Resultados entram nas operações auditadas e no relatório existente. Extratos em staging são descartados em falhas normais; originais permanecem intactos.

## Limitações desta etapa

Seleção é o perfil fixo acima, não busca arbitrária de membros. Não há executor Windows do backend, interpretação FTW2, reconstrução de QML ou análise Ghidra aprofundada adicionada por esta etapa.

Aquisição tem tarefa persistente, mas extração ainda não possui fila/checkpoints próprios para retomada no meio de um arquivo. Interrupção abrupta entre publicação dos arquivos e commit SQLite pode deixar diretório órfão; não reutilizá-lo como resultado validado. Fonte e diretório operacional devem permanecer protegidos de escrita concorrente. Esses pontos não devem ser apresentados como retomada completa ou sandbox de privilégios/rede.

Os testes reais usam instalador pequeno sintético; suporte de leitura até 1 GiB foi validado separadamente. Ainda falta ensaio NSIS real de 600 MiB e análise privada do VisionFT. Descobertas DSG e hashes externos do caso continuam não reproduzidos pelo Jarvis.
