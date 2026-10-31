"""Roteiro de teste pessoal (item 15): cenários sintéticos, saídas claras.

Pensado para o PROPRIETÁRIO rodar e entender, sem precisar ler JSON ou código.
Cada verificação imprime uma linha PASSOU/FALHOU em português; no fim, um
resumo honesto do que funcionou e do que ainda não está pronto. Não instala
nada, não usa rede, não toca em arquivos reais — tudo roda num diretório
temporário sintético, igual ao scripts/demo.py (que é o alvo técnico de CI;
este script é a versão legível para uma pessoa, pedida no relatório de
17/10/2026 após o PR #8: "teste pessoal sem login").

Saída: exit 0 se tudo passou; exit 1 e lista exata do que falhou, caso
contrário. Nunca inventa um resultado — cada falha mostra a exceção real.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cyber_core.errors import CoreError
from cyber_core.service import Core

CHECKS = []


def check(titulo):
    def wrap(fn):
        CHECKS.append((titulo, fn))
        return fn
    return wrap


def main():
    root = Path(tempfile.mkdtemp(prefix='cyber-core-try-me-'))
    inputs = root / 'inputs'
    inputs.mkdir()
    core = Core(root / 'state')
    ctx = {'core': core, 'root': root, 'inputs': inputs, 'case': None}

    print('CYBER CORE — roteiro de teste pessoal (sintético, sem rede, sem instalação)')
    print('Diretório temporário: ' + str(root))
    print()

    passed, failed = [], []
    for titulo, fn in CHECKS:
        try:
            fn(ctx)
            print('✅ PASSOU — ' + titulo)
            passed.append(titulo)
        except Exception as exc:
            print('❌ FALHOU — ' + titulo + ' (' + type(exc).__name__ + ': ' + str(exc) + ')')
            failed.append(titulo)

    core.close()
    print()
    print('Resumo: {} de {} verificações passaram.'.format(len(passed), len(CHECKS)))
    if failed:
        print('Falharam: ' + ', '.join(failed))
    print()
    print('Honestidade do estado (não é certificação de segurança nem perícia real):')
    print('- Tudo acima é sintético, offline, sem dados reais de cliente.')
    print('- Sem integração real de ferramentas profissionais (Ghidra/Nmap/Autopsy/etc.).')
    print('- Sem hardware, sem rede, sem execução de arquivo analisado.')
    print('- "platform_complete" seria false: a plataforma completa das 21 seções não está pronta.')
    return 0 if not failed else 1


@check('Criar investigação com autorização e escopo declarados')
def _(ctx):
    ctx['case'] = ctx['core'].investigate('teste-pessoal', 'Verificação sintética de capacidades',
                                          str(ctx['inputs']), 'proprietario', 'Roteiro de teste pessoal')


@check('Analisar um arquivo sintético e conferir o hash')
def _(ctx):
    sample = ctx['inputs'] / 'arquivo.bin'
    sample.write_bytes(b'\x7fELF' + bytes(range(256)) * 8)
    task = ctx['core'].enqueue(ctx['case'], sample, tool='analyze-file')
    out = ctx['core'].run_one(ctx['case'], task_id=task)
    assert out['copy_verified'] and len(out['sha256']) == 64
    ctx['first_result'] = out


@check('Classificar o tipo de investigação e criar um plano')
def _(ctx):
    plan = ctx['core'].plan(ctx['case'])
    assert plan['steps']


@check('Auditoria estática de configuração detecta segredo exposto (e o redige)')
def _(ctx):
    cfg = ctx['inputs'] / 'config.ini'
    cfg.write_text('password=SenhaSuperSecreta123\nDEBUG=true\n', encoding='utf-8')
    out = ctx['core'].audit_config(ctx['case'], str(cfg))
    assert out['summary']['high'] >= 1
    assert 'SenhaSuperSecreta123' not in str(out)


@check('Auditoria de implementação criptográfica detecta modo ECB inseguro')
def _(ctx):
    src = ctx['inputs'] / 'crypto.py'
    src.write_text('cipher = AES.new(key, AES.MODE_ECB)\n', encoding='utf-8')
    out = ctx['core'].audit_crypto_implementation(ctx['case'], str(src))
    assert any(f['kind'] == 'ecb_mode' for f in out['findings'])


@check('Autoteste de recuperação: senha fraca própria é recuperada honestamente')
def _(ctx):
    ctx['core'].set_authorization_basis(ctx['case'], kind='owner_consent', authority='proprietario',
                                        reference='teste pessoal', examiner='proprietario', scope_note='arquivo proprio')
    envelope = ctx['core'].make_lab_envelope(ctx['case'], str(ctx['inputs'] / 'cofre.ccpw1'),
                                             passphrase='abc123', content=b'segredo de laboratorio')
    out = ctx['core'].self_test_recovery(ctx['case'], envelope['path'], ['errado', 'abc123', 'outro'])
    assert out['recovery_demonstrated'] is True


@check('Demonstração real de RSA, ECC (ECDH) e ChaCha20-Poly1305')
def _(ctx):
    from cyber_core.cryptanalysis.algorithms import demonstrate_all
    out = demonstrate_all()
    assert out['rsa_oaep']['round_trip_ok'] and out['ecdh_aesgcm']['round_trip_ok'] and out['chacha20_poly1305']['round_trip_ok']


@check('Backup e restauração em diretório novo preservam os dados')
def _(ctx):
    backup_file = ctx['root'] / 'backup.sqlite3'
    ctx['core'].backup(str(backup_file))
    restored_home = ctx['root'] / 'restaurado'
    restored = Core.restore(restored_home, str(backup_file))
    try:
        assert restored.get(ctx['case'])['project'] == 'teste-pessoal'
        assert restored.verify_audit(ctx['case'])
    finally:
        restored.close()


@check('Cadeia de auditoria permanece íntegra até o fim')
def _(ctx):
    assert ctx['core'].verify_audit(ctx['case'])


if __name__ == '__main__':
    raise SystemExit(main())
