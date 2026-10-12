"""Launcher local PT-BR: conversa direta ou ativacao pelo nome Jarvis."""
from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import unicodedata
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'jarvis'
URL = 'http://127.0.0.1:8000'


def is_wake_phrase(text: str) -> bool:
    normalized = ''.join(c for c in unicodedata.normalize('NFKD', text.casefold())
                         if not unicodedata.combining(c))
    return bool(re.search(r'\bjarvis\b', normalized))


def is_stop_phrase(text: str) -> bool:
    words = re.findall(r'\w+', text.casefold())
    return ' '.join(words) in {'encerrar conversa', 'voltar a esperar'}


def parse_device(value: str):
    if not value.strip():
        return None
    if value.strip().lstrip('-').isdigit():
        number = int(value)
        if number < 0:
            raise ValueError('JARVIS_MIC deve ser um numero nao negativo ou nome do microfone.')
        return number
    return value.strip()


def build_parser():
    parser = argparse.ArgumentParser(description='Jarvis local em portugues do Brasil.')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--listen', action='store_true', help='Ativar falando Jarvis.')
    modes.add_argument('--text', action='store_true', help='Conversa por texto.')
    modes.add_argument('--web', action='store_true', help='Abrir a interface web.')
    modes.add_argument('--doctor', action='store_true', help='Verificar instalacao.')
    modes.add_argument('--stop', action='store_true', help='Parar o servidor web.')
    modes.add_argument('--list-mics', action='store_true', help='Listar microfones.')
    return parser


def cli(arguments):
    # Same interpreter preserves sounddevice.default.device for voice chat.
    from openjarvis.cli import cli as command
    command.main(args=arguments, prog_name='jarvis', standalone_mode=False)


def voice_chat():
    # Upstream asks for Enter before recording. Replace just its input reader
    # in this process; preserve the upstream engine, security and TTS.
    from openjarvis.cli import chat_cmd
    from openjarvis.cli._voice_chat import record_voice, speak, VoiceSession
    from openjarvis.speech import _tts_discovery
    from rich.console import Console
    original = chat_cmd.read_voice_input
    original_session = chat_cmd.VoiceSession
    original_order = _tts_discovery.TTS_BACKEND_ORDER
    session = VoiceSession()
    def automatic_input(console, session):
        text = record_voice(console, session)
        return '/quit' if isinstance(text, str) and is_stop_phrase(text) else text
    chat_cmd.read_voice_input = automatic_input
    chat_cmd.VoiceSession = lambda *args, **kwargs: session
    _tts_discovery.TTS_BACKEND_ORDER = ('kokoro',)
    try:
        speak('Estou aqui. Como posso ajudar?', Console(), session)
        cli(['chat', '--engine', 'ollama', '--voice', '--skip-runtime-panel', '--system',
             'Voce e Jarvis, assistente local. Responda sempre em portugues do Brasil.'])
    finally:
        chat_cmd.read_voice_input = original
        chat_cmd.VoiceSession = original_session
        _tts_discovery.TTS_BACKEND_ORDER = original_order


def web():
    uv = shutil.which('uv')
    if not uv:
        raise RuntimeError('uv nao encontrado. Execute o instalador e abra outro terminal.')
    def healthy():
        try:
            with urllib.request.urlopen(URL + '/health', timeout=1) as response:
                return response.status == 200
        except OSError:
            return False
    if not healthy():
        log_dir = Path(os.environ['OPENJARVIS_HOME']) / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        with (log_dir / 'web.log').open('ab') as log:
            process = subprocess.Popen(
                [uv, 'run', '--no-sync', 'jarvis', 'serve', '--engine', 'ollama',
                 '--host', '127.0.0.1', '--port', '8000'],
                cwd=SOURCE, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
        for _ in range(60):
            if healthy():
                break
            if process.poll() is not None:
                raise RuntimeError(f'Servidor encerrou. Consulte {log_dir / "web.log"}.')
            time.sleep(0.5)
        else:
            process.terminate()
            raise RuntimeError(f'Servidor nao ficou pronto. Consulte {log_dir / "web.log"}.')
    webbrowser.open(URL)
    print(f'Interface: {URL}. Para parar: jarvis --stop.')


def listen():
    from faster_whisper import WhisperModel
    from openjarvis.speech.voice_io import record_until_silence
    print('Carregando Whisper local (base, CPU, int8); o primeiro uso baixa o modelo.')
    model = WhisperModel('base', device='cpu', compute_type='int8')
    print('Diga Jarvis e aguarde o aviso antes da pergunta. Ctrl+C encerra.')
    while True:
        audio = record_until_silence(startup_silence_seconds=3, max_seconds=6,
                                     silence_seconds=0.6)
        segments, _ = model.transcribe(io.BytesIO(audio), language='pt',
                                      vad_filter=True, beam_size=1)
        text = ' '.join(segment.text for segment in segments)
        if not is_wake_phrase(text):
            continue
        print('Jarvis ativado. Diga "encerrar conversa" para voltar a esperar pelo nome.')
        try:
            import sounddevice as sd
            import soundfile as sf
            jingle = ROOT / 'voice' / 'assets' / 'jingle.mp3'
            if jingle.is_file():
                sound, rate = sf.read(jingle, dtype='float32')
                sd.play(sound, rate)
                sd.wait()
        except Exception as exc:
            print(f'Nao foi possivel tocar o jingle: {exc}', file=sys.stderr)
        voice_chat()
        print('Ouvindo Jarvis novamente. Ctrl+C encerra.')


def main():
    arguments = build_parser().parse_args()
    os.environ.setdefault('OPENJARVIS_HOME', str(ROOT / '.state'))
    os.environ.setdefault('JARVIS_SKIP_MODEL_PICK', '1')
    os.environ.setdefault('DO_NOT_TRACK', '1')
    os.environ.setdefault('OPENJARVIS_NO_UPDATE_CHECK', '1')
    os.chdir(SOURCE)
    if arguments.web:
        web()
        return
    if arguments.doctor:
        cli(['doctor'])
        return
    if arguments.stop:
        cli(['stop'])
        return
    if arguments.text:
        cli(['chat', '--engine', 'ollama', '--skip-runtime-panel'])
        return
    import sounddevice as sd
    if arguments.list_mics:
        print(sd.query_devices())
        return
    mic = parse_device(os.environ.get('JARVIS_MIC', ''))
    if mic is not None:
        sd.default.device = (mic, sd.default.device[1])
    if arguments.listen:
        listen()
    else:
        voice_chat()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nJarvis encerrado.')
    except Exception as exc:
        print(f'Erro: {exc}', file=sys.stderr)
        sys.exit(1)
