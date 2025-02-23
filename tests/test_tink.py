# -*- encoding: utf-8 -*-
"""Test module

"""
import os
import io
from random import randbytes
import tarfile
import lzma
import bz2
import zipfile
import struct

import tink
from tink import aead
from tink import secret_key_access

from tinkfile import TinkFile, open as tink_open

import pytest


@pytest.mark.parametrize("chunk_size, file_size",
    [
        (1024 * 1, 1024 * 10), (1024 * 1, 1024 * 10 + 4), (1024 * 1, 1024 * 10 + 5),
        (1024 * 10, 1024 * 10), (1024 * 10, 1024 * 10 + 7), (1024 * 10, 1024 * 10 + 3),
        (1024 * 100, 1024 * 10), (1024 * 100, 1024 * 10 + 9), (1024 * 100, 1024 * 10 + 11),
    ])
def test_buffer_aes_file(random_path, random_name, chunk_size, file_size):
    aead.register()
    key_template = aead.aead_key_templates.AES128_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    key = tink.json_proto_keyset_format.serialize(
            keyset_handle, secret_key_access.TOKEN
        )

    data = randbytes(file_size)
    dataf = os.path.join(random_path, random_name)
    with TinkFile(dataf, mode='wb', tink_key=key, chunk_size=chunk_size) as ff:
        ff.write(data)
    with open(dataf, "rb") as ff:
        datar = ff.read()
    assert data != datar
    with TinkFile(dataf, "rb", tink_key=key) as ff:
        datar = ff.read()
    assert data == datar

    data = random_name * 2
    dataf = os.path.join(random_path, random_name)
    with tink_open(dataf, mode='wt', tink_key=key, chunk_size=chunk_size) as ff:
        ff.write(data)
    with open(dataf, "rb") as ff:
        datar = ff.read()
    assert data != datar
    with tink_open(dataf, "rt", tink_key=key) as ff:
        datar = ff.read()
    assert data == datar

@pytest.mark.parametrize("chunk_size, file_size",
    [
        (1024 * 1, 1024 * 10), (1024 * 1, 1024 * 10 + 4), (1024 * 1, 1024 * 10 + 5),
        (1024 * 10, 1024 * 10), (1024 * 10, 1024 * 10 + 7), (1024 * 10, 1024 * 10 + 3),
        (1024 * 100, 1024 * 10), (1024 * 100, 1024 * 10 + 9), (1024 * 100, 1024 * 10 + 11),
    ])
def test_buffer_tink_open(random_path, random_name, chunk_size, file_size):
    aead.register()
    key_template = aead.aead_key_templates.AES128_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    key = tink.json_proto_keyset_format.serialize(
            keyset_handle, secret_key_access.TOKEN
        )

    data = randbytes(file_size)
    dataf = os.path.join(random_path, random_name)
    with tink_open(dataf, mode='wb', tink_key=key, chunk_size=chunk_size) as ff:
        ff.write(data)
    with open(dataf, "rb") as ff:
        datar = ff.read()
    assert data != datar
    with tink_open(dataf, "rb", tink_key=key) as ff:
        datar = ff.read()
    assert data == datar

    data = random_name * 2
    dataf = os.path.join(random_path, random_name)
    with tink_open(dataf, mode='wt', tink_key=key, chunk_size=chunk_size) as ff:
        ff.write(data)
    with open(dataf, "rb") as ff:
        datar = ff.read()
    assert data != datar
    with tink_open(dataf, "rt", tink_key=key) as ff:
        datar = ff.read()
    assert data == datar


def test_bad(random_path, random_name):
    aead.register()
    key_template = aead.aead_key_templates.AES128_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    key = tink.json_proto_keyset_format.serialize(
            keyset_handle, secret_key_access.TOKEN
        )
    data = randbytes(128)
    dataf = os.path.join(random_path, 'test_bad_%s.frnt'%random_name)
    dataok = os.path.join(random_path, 'test_ok_%s.frnt'%random_name)

    with TinkFile(dataok, mode='wb', tink_key=key) as ff:
        assert repr(ff).startswith('<TinkFile')

    with pytest.raises(ValueError):
        with TinkFile(dataf, mode='wbt', tink_key=key) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with TinkFile(dataf, mode='zzz', tink_key=key) as ff:
            ff.write(data)

    with pytest.raises(FileNotFoundError):
        with TinkFile(None, mode='wb', tink_key=key) as ff:
            ff.write(data)

    with pytest.raises(FileNotFoundError):
        with TinkFile(dataf, tink_key=key) as ff:
            data = ff.read()

    with pytest.raises(ValueError):
        with tink_open(dataf, mode='wbt', tink_key=key) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with tink_open(dataf, mode='wb', tink_key=key, encoding='utf-8') as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with tink_open(dataf, mode='wb', tink_key=key, errors=True) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with tink_open(dataf, mode='wb', tink_key=key, newline='\n') as ff:
            ff.write(data)

    with pytest.raises(TypeError):
        with tink_open(None, mode='wb', tink_key=key) as ff:
            ff.write(data)

    with pytest.raises(ValueError):
        with tink_open(dataf, mode='wb', tink_key=None) as ff:
            ff.write(data)
