"""Checks local speech models without reading microphone audio."""
from pathlib import Path
import os

import sounddevice as sd
from faster_whisper import WhisperModel
from openjarvis.speech.kokoro_tts import KokoroTTSBackend

print('Microfones e alto-falantes disponiveis:')
print(sd.query_devices())
WhisperModel('base', device='cpu', compute_type='int8')
backend = KokoroTTSBackend(device='cpu')
try:
    result = backend.synthesize('Ola! Eu sou o Jarvis. Como posso ajudar voce?',
                                voice_id='pf_dora', output_format='wav')
    if not result.audio:
        raise RuntimeError('Kokoro nao retornou audio.')
    output = Path(os.environ['OPENJARVIS_HOME']) / 'voice-test.wav'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(result.audio)
    print(f'Voz pf_dora sintetizada em {output}. Teste a conversa com jarvis.')
finally:
    backend.close()
