import os
from unittest import TestCase

from pycryptoprosdk import Hash
from tests.utils import get_content

files_dir = os.path.join(os.path.dirname(__file__), 'files')


class HashTestCase(TestCase):
    def test_hash_CALG_GR3411(self):
        content = 'Данные для подписи\n'
        self.assertEqual(
            Hash().create_hash(content, 'CALG_GR3411'),
            '445888F2DEA25B3AD0187186CC18BD74D79CEF78498EF308755459AFE4552EBA'
        )

        content = get_content(os.path.join(files_dir, 'img.png'))
        self.assertEqual(
            Hash().create_hash(content, 'CALG_GR3411'),
            '799025F048414BD20681D41EDFEE3158D7D5B14DDCB17912E38DE0B620C353B7'
        )

    def test_hash_CALG_GR3411_2012_256(self):
        content = 'Данные для подписи\n'

        self.assertEqual(
            Hash().create_hash(content, 'CALG_GR3411_2012_256'),
            'AE943FBB2751DB601DEB5D90740CEA221B2EE0CD9A2A0D16E0F3A13DB78A02B5'
        )

    def test_hash_CALG_GR3411_2012_512(self):
        content = 'Данные для подписи\n'

        self.assertEqual(
            Hash().create_hash(content, 'CALG_GR3411_2012_512'),
            '32C1304E914F0616063D7765EBA5C81F907AB8CD684C0787ED9445DD74B8CD95A5C286B249EE338CFAA3F446057B6107E151596BC0240474BC342160F2440089'
        )
