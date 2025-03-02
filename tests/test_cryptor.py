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

@pytest.mark.skip(reason="no derive implemented")
def test_cryptor_class(random_path, random_name):
    derive = Cryptor.derive('test')
    with pytest.raises(ValueError):
        derive = Cryptor.derive(None)

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

@pytest.mark.skip(reason="no derive implemented")
def test_cryptor_derive(random_path, random_name):
    import secrets
    salt, derive1 = Cryptor.derive('test')
    _, derive2 = Cryptor.derive('test', salt=salt)
    crypt1 = Cryptor(tink_key=derive1)
    crypt2 = Cryptor(tink_key=derive2)
    text = secrets.token_bytes(1785)
    crypted = crypt1._encrypt(text)
    uncrypted = crypt1._decrypt(crypted)
    assert uncrypted == text
    uncrypted = crypt2._decrypt(crypted)
    assert uncrypted == text
