[![CircleCI](https://dl.circleci.com/status-badge/img/gh/bibi21000/TinkFile/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/bibi21000/TinkFile/tree/main)
[![codecov](https://codecov.io/gh/bibi21000/TinkFile/graph/badge.svg?token=4124GIOJAK)](https://codecov.io/gh/bibi21000/TinkFile)
![PyPI - Downloads](https://img.shields.io/pypi/dm/aesfile)

# TinkFile

A python xxxFile like (ie TarFile, GzipFile, BZ2File, pyzstd.ZstdFile, ...)
for encrypting files with cryptography Tink.

This project is part of the CofferFile : https://github.com/bibi21000/CofferFile

If you're looking for a more powerfull storage for your sensible datas,
look at PyCoffer : https://github.com/bibi21000/PyCoffer.


## Install

```
    pip install aesfile
```

## Create your encryption key

```
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(16)
```
and store it in a safe place (disk, database, ...).

This key is essential to encrypt and decrypt data.
Losing this key means losing the data.

## "open" your encrypted files like normal files

Text files :

```
    import aesfile

    with aesfile.open('test.txc', mode='wt', aes_key=key, encoding="utf-8") as ff:
        ff.write(data)

    with aesfile.open('test.txc', "rt", aes_key=key, encoding="utf-8") as ff:
        data = ff.read()

    with aesfile.open('test.txc', mode='wt', aes_key=key, encoding="utf-8") as ff:
        ff.writelines(data)

    with aesfile.open('test.txc', "rt", aes_key=key, encoding="utf-8") as ff:
        data = ff.readlines()
```

Binary files :

```
    import aesfile

    with aesfile.open('test.dac', mode='wb', aes_key=key) as ff:
        ff.write(data)

    with aesfile.open('test.dac', "rb", aes_key=key) as ff:
        data = ff.read()
```

## Or compress and crypt them with pyzstd

```
    pip install aesfile[zstd]
```

```
    from aesfile.zstd import TinkFile

    with TinkFile('test.dac', mode='wb', aes_key=key) as ff:
        ff.write(data)

    with TinkFile('test.dac', mode='rb', aes_key=key) as ff:
        data = ff.read()
```

## And chain it to tar and bz2

```
class TarBz2TinkFile(tarfile.TarFile):

    def __init__(self, name, mode='r', aes_key=None, chunk_size=aesfile.CHUNK_SIZE, **kwargs):
        compresslevel = kwargs.pop('compresslevel', 9)
        self.fernet_file = aesfile.TinkFile(name, mode,
            aes_key=aes_key, chunk_size=chunk_size, **kwargs)
        try:
            self.bz2_file = bz2.BZ2File(self.fernet_file, mode=mode,
                compresslevel=compresslevel, **kwargs)
            try:
                super().__init__(fileobj=self.bz2_file, mode=mode, **kwargs)

            except Exception:
                self.bz2_file.close()
                raise

        except Exception:
            self.fernet_file.close()
            raise

    def close(self):
        try:
            super().close()
        finally:
            try:
                if self.fernet_file is not None:
                    self.bz2_file.close()
            finally:
                if self.fernet_file is not None:
                    self.fernet_file.close()

    with TarBz2TinkFile('test.zsc', mode='wb', aes_key=key) as ff:
        ff.add(dataf1, 'file1.out')
        ff.add(dataf2, 'file2.out')

    with TarBz2TinkFile('test.zsc', mode='rb', aes_key=key) as ff:
        fdata1 = ff.extractfile('file1.out')
        fdata2 = ff.extractfile('file2.out')
```

## Encrypt / decrypt existing files

Encrypt :
```
    import aesfile

    with open(source, 'rb') as fin, aesfile.open(destination, mode='wb', aes_key=key) as fout:
        while True:
            data = fin.read(7777)
            if not data:
                break
            fout.write(data)
```

Decrypt :
```
    import aesfile

    with aesfile.open(source, mode='rb', aes_key=key) as fin, open(destination, 'wb') as fout :
        while True:
            data = fin.read(8888)
            if not data:
                break
            fout.write(data)
```

Or to compress and crypt

```
    import aesfile.zstd

    with open(source, 'rb') as fin, aesfile.zstd.open(destination, mode='wb', aes_key=key) as fout:
        while True:
            data = fin.read(7777)
            if not data:
                break
            fout.write(data)

    with aesfile.zstd.open(source, mode='rb', aes_key=key) as fin, open(destination, 'wb') as fout :
        while True:
            data = fin.read(8888)
            if not data:
                break
            fout.write(data)
```

Look at documentation : https://bibi21000.github.io/TinkFile/

