# -*- encoding: utf-8 -*-
"""Test module

"""
import os
import importlib
import time
from random import randbytes
import urllib.request
import zipfile
import tarfile

import tink
from tink import aead
from tink import secret_key_access

import tinkfile
from tinkfile import TinkFile
from tinkfile.zstd import TinkFile as _ZstdTinkFile, open as aesz_open
from tinkfile.tar import TarFile as _TarZstdTinkFile

import pytest


class ZstdTinkFile(_ZstdTinkFile):
    pass

class TarZstdTinkFile(_TarZstdTinkFile):
    pass

@pytest.mark.parametrize("fcls, size, nb", [
    (TarZstdTinkFile, 129, 100),
    (TarZstdTinkFile, 533, 20),
    (TarZstdTinkFile, 1089, 5),
])
def test_tar(random_path, fcls, size, nb):
    aead.register()
    key_template = aead.aead_key_templates.AES128_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    key = tink.json_proto_keyset_format.serialize(
            keyset_handle, secret_key_access.TOKEN
        )
    params = {
        'tink_key': key,
    }
    dataf = os.path.join(random_path, 'test.frnt')
    time_start = time.time()
    file_size = 0
    data1f = os.path.join(random_path, 'file.data')
    data1 = randbytes(size)
    with open(data1f, 'wb') as ff:
        ff.write(data1)
    with fcls(dataf, mode='w', **params) as ff:
        for i in range(nb):
            ff.add(data1f, "%s-%s"%(i, data1f))
            file_size += os.path.getsize(data1f)
    time_write = time.time()
    with fcls(dataf, "r", **params) as ff:
        ff.extractall('extract_tar')
    time_read = time.time()
    # ~ assert data == datar
    comp_size = os.path.getsize(dataf)
    for i in range(nb):
        with open(os.path.join('extract_tar', "%s-%s"%(i, data1f)),'rb') as ff:
            data1r = ff.read()
            assert data1 == data1r

