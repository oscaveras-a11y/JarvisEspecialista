# CYBER CORE: primeira entrega

O proprietário dispensou aprovações intermediárias e determinou implementação direta da especificação fornecida em 16/10/2026.

Arquitetura: pacote Python 3.12+, argparse, SQLite e cryptography para AES-256-GCM. Repositório privado oscaveras-a11y/J.A.R.V.I.S, main anterior e13049b0ba3368d3b31c772f97ef8d856950f37f. Preservar histórico ao substituir conteúdo.

1. Testar e implementar armazenamento, autorizações revogáveis, CLI e auditoria transacional.
2. Testar e implementar análise estática limitada, preservação de evidência, hipóteses, fila, checkpoint, pausa/retomada e relatório.
3. Testar e implementar recuperação AES-256-GCM de envelope sintético conhecido com chave fornecida, autenticação e auditoria sem segredos.
4. Implementar diagnóstico e adaptadores CLI opcionais com limites; distinguir testes sintéticos de integração real.
5. Executar suíte completa e teste em novo processo. Documentar resultados, limitações e fases pendentes; publicar somente código e documentação.

Revisão: caminhos UNC/device/ADS/traversal/reparse; revogação e validade; limites e arquivos alterados durante análise; retomada sem duplicação; chave/tag incorreta sem plaintext parcial.

Dados em CYBER_HOME externo ao checkout. SQLite não fornece criptografia nem identidade multiusuário. ACLs/BitLocker são responsabilidade operacional documentada. Não executar binários desconhecidos nem shell arbitrário. Agentes só recebem resumo explicitamente autorizado; suas respostas não viram comandos. Alta entropia não prova criptografia. Não registrar chaves, somente referência opaca.

Primeira entrega não conclui fases 2–6: worktrees/paralelismo/revisão independente, ferramentas externas, pesquisa online, CAN, perícia avançada e worker Windows serão declarados pendentes quando ausentes. AES suporta apenas envelope definido; não quebra AES nem recupera universalmente contêineres.
