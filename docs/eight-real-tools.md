# Oito ferramentas reais no mesmo ambiente

A validação `Eight real tools together` instala e executa as oito ferramentas no mesmo runner Linux temporário do GitHub: Ghidra, Binwalk, Hashcat, John Jumbo, QPDF, OpenSSL, Detect It Easy (diec) e Unblob. Os adaptadores existentes do CORE são utilizados; não basta o executável responder à versão.

## Critérios exigidos

- Ghidra descompila ELF e PE sintéticos com constante conhecida 42. Binwalk encontra gzip conhecido no offset 256. Cópia verificada, SQLite, auditoria e relatório são exigidos por `scripts/check-real-backends.py`.
- Hashcat e John confirmam candidatas conhecidas em hashes e ZIP sintéticos, incluindo candidata errada antes da correta. QPDF verifica PDF protegido; OpenSSL verifica PKCS12/PFX. DIE identifica ELF e Unblob identifica TAR. `tests/test_external_recovery_tools.py` exige resultados reais, auditoria e persistência.
- RAR5 com conteúdo ou cabeçalhos protegidos exige verificação nativa e perfil John sobre arquivos sintéticos gerados no runner. O verificador de senha não comprova integridade integral do payload.
- A suíte completa e a demonstração são executadas com as oito ferramentas instaladas. Ausência ou falha nos testes reais impede aprovação do job. Skips de plataforma em outros módulos continuam identificados como skips.

## Operação e limites

São ferramentas chamadas sob demanda pelo CORE, não oito serviços que precisam ficar executando ociosos. O runner é descartado após o teste; isso não mantém um servidor nem um painel permanentemente online. O PR do painel conectado continua separado.

As ferramentas externas são validadas em Linux com CPU. O suporte do núcleo e dos formatos internos a Windows não equivale a validar todos os executáveis externos nativos em Windows. A validação usa somente amostras sintéticas; não comprova recuperação de firmware automotivo proprietário nem recuperação universal de senhas.

Ghidra/Binwalk têm versões e hashes de download fixados no script de preparação. As seis outras ferramentas preservam a preparação existente e seus próprios limites. Nenhum arquivo de cliente, senha real ou credencial de agente é necessário. Nada é instalado no computador do proprietário.

## Evidência

Consulte o check `Eight real tools together` do commit exato do PR. Seu job `real_tools` deve terminar com sucesso, incluindo as etapas de descompilação, RAR5 e recuperação/identificação. Uma execução histórica, um check apenas de contratos ou um PR em rascunho não comprovam a aprovação de um novo commit.
