# Laboratório HTTP no CORE
Comando: cyber --home DIRETORIO web-lab CASO manifesto.json.
Manifesto dentro do escopo do caso:
{"origin":"http://127.0.0.1:PORTA","allow_write":true}

Somente servidor sintético descartável com GET/POST /lab/content e JSON title.
Autorização, pausa e hash do manifesto são conferidos antes de cada requisição.
Resultado, origem e hash são persistidos na operação auditada e relatório.
Revogação, expiração ou cancelamento impedem a próxima requisição.
Uma requisição em andamento pode esperar até10s; não há cancelamento
instantâneo do socket nem garantia transacional de restauração.
Após revogação/pausa, nenhuma restauração adicional é enviada; o evento
web_lab_interrupted informa possível limpeza pendente. Descartar a fixture
antes de retomar. Encerramento abrupto também pode deixar alteração pendente.

Limites: cinco requisições, resposta64KiB, manifesto4KiB, loopback literal,
porta alta, sem redirecionamento/proxy/DNS. A API audit permanece harness
de baixo nível; a CLI principal usa CORE. Não opera sites reais e não é
motor geral de exploração. Desenvolvimento/testes somente no GitHub.
