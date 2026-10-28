# Laboratório web sintético

Primeiro incremento de transporte HTTP e testes (seções Codex10/18).
Não substitui o motor de vulnerabilidades da seção9, atribuído ao Claude.

Executar no runner GitHub: python -m cyber_core.web_lab http://127.0.0.1:PORTA.
O servidor sintético deve oferecer GET/POST /lab/content com JSON title.
O runner tenta uma alteração sem credenciais, confirma por leitura e tenta
restaurar o título original em finally, confirmando novamente por leitura.
Falhas durante restauração são erros; não há garantia de restauração após
encerramento abrupto. Usar somente dados descartáveis no laboratório.

Somente IPv4 loopback literal e porta >=1024; sem DNS, proxy, redirecionamento
ou alvos públicos. Até cinco requisições, resposta64KiB e prazo10s.
JSON com observação, restauração e limitações. Não opera Amorella.
Ainda pendentes: autorização persistente CORE, auditoria, cancelamento,
interface principal, laboratório protegido de contraste e motor completo.
Este incremento não declara o Jarvis completo nem uma ferramenta geral
capaz de invadir ou modificar sites reais.
