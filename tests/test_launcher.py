import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'voice' / 'launcher.py'
spec = importlib.util.spec_from_file_location('launcher', SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class LauncherTests(unittest.TestCase):
    def test_name_with_greeting_and_punctuation(self):
        for text in ('Jarvis', 'Oi, JARVIS!', 'Olá Jarvis, pode me ouvir?', 'Járvis.'):
            self.assertTrue(module.is_wake_phrase(text), text)

    def test_unrelated_words_do_not_activate(self):
        for text in ('', 'bom dia', 'jarvisado', 'superjarvis', 'jarvis123'):
            self.assertFalse(module.is_wake_phrase(text), text)

    def test_input_device_id_or_name(self):
        self.assertIsNone(module.parse_device(''))
        self.assertEqual(module.parse_device('2'), 2)
        self.assertEqual(module.parse_device('Microfone USB'), 'Microfone USB')
        with self.assertRaises(ValueError):
            module.parse_device('-1')

    def test_end_session_phrases(self):
        for text in ('Encerrar conversa.', 'Voltar a esperar', 'ENCERRAR CONVERSA!'):
            self.assertTrue(module.is_stop_phrase(text), text)
        self.assertFalse(module.is_stop_phrase('Nao quero encerrar conversa agora'))

    def test_default_is_voice_and_modes_are_exclusive(self):
        parser = module.build_parser()
        self.assertFalse(parser.parse_args([]).listen)
        self.assertTrue(parser.parse_args(['--listen']).listen)
        with self.assertRaises(SystemExit):
            parser.parse_args(['--listen', '--text'])

    def test_voice_session_uses_microphone_without_enter_and_restores_upstream(self):
        original_reader = object()
        original_session = object()
        chat = SimpleNamespace(read_voice_input=original_reader, VoiceSession=original_session)
        discovery = SimpleNamespace(TTS_BACKEND_ORDER=('kokoro', 'openai_tts'))
        session = object()
        fake_modules = {
            'openjarvis': SimpleNamespace(),
            'openjarvis.cli': SimpleNamespace(chat_cmd=chat),
            'openjarvis.cli._voice_chat': SimpleNamespace(
                record_voice=lambda console, session: 'encerrar conversa',
                speak=lambda *args: None, VoiceSession=lambda: session),
            'openjarvis.speech': SimpleNamespace(_tts_discovery=discovery),
            'rich.console': SimpleNamespace(Console=lambda: object()),
        }
        def run_chat(arguments):
            self.assertEqual(chat.read_voice_input(None, session), '/quit')
            self.assertIs(chat.VoiceSession(None), session)
            self.assertEqual(discovery.TTS_BACKEND_ORDER, ('kokoro',))
            raise RuntimeError('simulated engine failure')
        with patch.dict(sys.modules, fake_modules), patch.object(module, 'cli', run_chat):
            with self.assertRaisesRegex(RuntimeError, 'simulated engine failure'):
                module.voice_chat()
        self.assertIs(chat.read_voice_input, original_reader)
        self.assertIs(chat.VoiceSession, original_session)
        self.assertEqual(discovery.TTS_BACKEND_ORDER, ('kokoro', 'openai_tts'))


if __name__ == '__main__':
    unittest.main()
