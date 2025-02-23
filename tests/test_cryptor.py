# -*- encoding: utf-8 -*-
"""Test module

"""
import os
import io

import tink
from tink import aead
from tink import secret_key_access

from tinkfile import TinkCryptor as Cryptor

import pytest


def test_cryptor(random_path, random_name):
    aead.register()
    key_template = aead.aead_key_templates.AES128_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    key = tink.json_proto_keyset_format.serialize(
            keyset_handle, secret_key_access.TOKEN
        )
    cryptor = Cryptor(tink_key=key)
    derive = cryptor.derive('test')

def test_cryptor_bad(random_path, random_name):
    aead.register()
    key_template = aead.aead_key_templates.AES128_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    key = tink.json_proto_keyset_format.serialize(
            keyset_handle, secret_key_access.TOKEN
        )
    cryptor = Cryptor(tink_key=key)

    # ~ with pytest.raises(TypeError):
    derive = cryptor.derive(None)
