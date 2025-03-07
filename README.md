[![CircleCI](https://dl.circleci.com/status-badge/img/gh/bibi21000/TinkFile/tree/main.svg?style=shield)](https://dl.circleci.com/status-badge/redirect/gh/bibi21000/TinkFile/tree/main)
[![CodeQL](https://github.com/bibi21000/TinkFile/actions/workflows/codeql.yml/badge.svg)](https://github.com/bibi21000/TinkFile/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/bibi21000/TinkFile/graph/badge.svg?token=4124GIOJAK)](https://codecov.io/gh/bibi21000/TinkFile)
![PyPI - Downloads](https://img.shields.io/pypi/dm/tinkfile)

# TinkFile

A python xxxFile like (ie TarFile, GzipFile, BZ2File, pyzstd.ZstdFile, ...)
for encrypting files with cryptography Tink (experimental).

This project is part of the CofferFile : https://github.com/bibi21000/CofferFile

If you're looking for a more powerfull storage for your sensible datas,
look at PyCoffer : https://github.com/bibi21000/PyCoffer.


## Install

```
    pip install tinkfile
```

## Create your encryption key in json format

```
    import tink
    from tink import aead
    from tink import secret_key_access

    aead.register()
    key_template = aead.aead_key_templates.AES128_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    key = tink.json_proto_keyset_format.serialize(
            keyset_handle, secret_key_access.TOKEN
        )

```
and store it in a safe place (disk, database, ...).

This key is essential to encrypt and decrypt data.
Losing this key means losing the data.

## "open" your encrypted files like normal files

Text files :

```
    import tinkfile

    with tinkfile.open('test.txc', mode='wt', tink_key=key, encoding="utf-8") as ff:
        ff.write(data)

    with tinkfile.open('test.txc', "rt", tink_key=key, encoding="utf-8") as ff:
        data = ff.read()

    with tinkfile.open('test.txc', mode='wt', tink_key=key, encoding="utf-8") as ff:
        ff.writelines(data)

    with tinkfile.open('test.txc', "rt", tink_key=key, encoding="utf-8") as ff:
        data = ff.readlines()
```

Binary files :

```
    import tinkfile

    with tinkfile.open('test.dac', mode='wb', tink_key=key) as ff:
        ff.write(data)

    with tinkfile.open('test.dac', "rb", tink_key=key) as ff:
        data = ff.read()
```

## Or compress and crypt them with pyzstd

Look at https://github.com/bibi21000/CofferFile/blob/main/BENCHMARK.md.

```
    pip install tinkfile[zstd]
```

```
    from tinkfile.zstd import TinkFile

    with TinkFile('test.dac', mode='wb', tink_key=key) as ff:
        ff.write(data)

    with TinkFile('test.dac', mode='rb', tink_key=key) as ff:
        data = ff.read()
```

## And chain it to tar and bz2

```
class TarBz2TinkFile(tarfile.TarFile):

    def __init__(self, name, mode='r', tink_key=None, chunk_size=tinkfile.CHUNK_SIZE, **kwargs):
        compresslevel = kwargs.pop('compresslevel', 9)
        self.tink_file = tinkfile.TinkFile(name, mode,
            tink_key=tink_key, chunk_size=chunk_size, **kwargs)
        try:
            self.bz2_file = bz2.BZ2File(self.tink_file, mode=mode,
                compresslevel=compresslevel, **kwargs)
            try:
                super().__init__(fileobj=self.bz2_file, mode=mode, **kwargs)

            except Exception:
                self.bz2_file.close()
                raise

        except Exception:
            self.tink_file.close()
            raise

    def close(self):
        try:
            super().close()
        finally:
            try:
                if self.tink_file is not None:
                    self.bz2_file.close()
            finally:
                if self.tink_file is not None:
                    self.tink_file.close()

    with TarBz2TinkFile('test.zsc', mode='wb', tink_key=key) as ff:
        ff.add(dataf1, 'file1.out')
        ff.add(dataf2, 'file2.out')

    with TarBz2TinkFile('test.zsc', mode='rb', tink_key=key) as ff:
        fdata1 = ff.extractfile('file1.out')
        fdata2 = ff.extractfile('file2.out')
```

## Encrypt / decrypt existing files

Encrypt :
```
    import tinkfile

    with open(source, 'rb') as fin, tinkfile.open(destination, mode='wb', tink_key=key) as fout:
        while True:
            data = fin.read(7777)
            if not data:
                break
            fout.write(data)
```

Decrypt :
```
    import tinkfile

    with tinkfile.open(source, mode='rb', tink_key=key) as fin, open(destination, 'wb') as fout :
        while True:
            data = fin.read(8888)
            if not data:
                break
            fout.write(data)
```

Or to compress and crypt

```
    import tinkfile.zstd

    with open(source, 'rb') as fin, tinkfile.zstd.open(destination, mode='wb', tink_key=key) as fout:
        while True:
            data = fin.read(7777)
            if not data:
                break
            fout.write(data)

    with tinkfile.zstd.open(source, mode='rb', tink_key=key) as fin, open(destination, 'wb') as fout :
        while True:
            data = fin.read(8888)
            if not data:
                break
            fout.write(data)
```

Look at documentation : https://bibi21000.github.io/TinkFile/

