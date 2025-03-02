# -*- encoding: utf-8 -*-
"""

.. include:: ../README.md
   :start-line: 1


"""
__author__ = 'bibi21000 aka Sébastien GALLET'
__email__ = 'bibi21000@gmail.com'

__all__ = ["TinkCryptor", "TinkFile", "open"]

from cofferfile import EncryptFile, Cryptor, _open_t
from cofferfile import WRITE_BUFFER_SIZE, CHUNK_SIZE, READ, WRITE, APPEND, EXCLUSIVE # noqa F401
from cofferfile.decorator import reify

class TinkFile(EncryptFile):
    """
    `tinkfile.zstd`
    `tinkfile.tar`
    """

    def __init__(self, filename=None, mode=None, fileobj=None,
            chunk_size=CHUNK_SIZE, write_buffer_size=WRITE_BUFFER_SIZE,
            tink_key=None,
        ):
        """Constructor for the TinkFile class.

        At least one of fileobj and filename must be given a
        non-trivial value.

        The new class instance is based on fileobj, which can be a regular
        file, an io.BytesIO object, or any other object which simulates a file.
        It defaults to None, in which case filename is opened to provide
        a file object.

        When fileobj is not None, the filename argument is only used to be
        included in the gzip file header, which may include the original
        filename of the uncompressed file.  It defaults to the filename of
        fileobj, if discernible; otherwise, it defaults to the empty string,
        and in this case the original filename is not included in the header.

        The mode argument can be any of 'r', 'rb', 'a', 'ab', 'w', 'wb', 'x', or
        'xb' depending on whether the file will be read or written.  The default
        is the mode of fileobj if discernible; otherwise, the default is 'rb'.
        A mode of 'r' is equivalent to one of 'rb', and similarly for 'w' and
        'wb', 'a' and 'ab', and 'x' and 'xb'.

        The tink_key argument is the AES key used to crypt/decrypt data.

        Encryption is done by chunks to reduce memory footprint. The default
        chunk_size is 64KB.
        """
        super().__init__(filename=filename, mode=mode, fileobj=fileobj,
            chunk_size=chunk_size, write_buffer_size=write_buffer_size,
            cryptor='tink', tink_key=tink_key)

    def __repr__(self):
        s = repr(self.myfileobj)
        return '<TinkFile ' + s[1:-1] + ' ' + hex(id(self)) + '>'


class TinkCryptor(Cryptor):
    """
    From https://github.com/tink-crypto/tink-py/blob/main/examples/cleartext_keyset/cleartext_keyset_cli.py
    """

    @reify
    def _imp_tink(cls):
        """Lazy loader for tink"""
        import importlib
        return importlib.import_module('tink')

    @reify
    def _imp_tink_secret_key_access(cls):
        """Lazy loader for tink.secret_key_access"""
        import importlib
        return importlib.import_module('tink.secret_key_access')

    @reify
    def _imp_tink_aead(cls):
        """Lazy loader for tink.aead"""
        import importlib
        return importlib.import_module('tink.aead')

    def __init__(self, tink_key=None, **kwargs):
        super().__init__(**kwargs)
        if tink_key is None:
            raise ValueError("Invalid tink_key: {!r}".format(tink_key))
        self._imp_tink_aead.register()
        self.tink_key = tink_key
        keyset_handle = self._imp_tink.json_proto_keyset_format.parse(
            self.tink_key, self._imp_tink_secret_key_access.TOKEN
        )
        self.cipher = keyset_handle.primitive(self._imp_tink_aead.Aead)

    @classmethod
    def derive(self, password, salt=None, key_len=64, N=2 ** 14, r=8, p=1, num_keys=1):
        """Derive a key from password (experimental)
        """
        return salt, None

    def _decrypt(self, chunk):
        return self.cipher.decrypt(chunk, b'envelope_chunk')

    def _encrypt(self, chunk):
        return self.cipher.encrypt(chunk, b'envelope_chunk')

def open(filename, mode="rb", tink_key=None,
         encoding=None, errors=None, newline=None,
         chunk_size=CHUNK_SIZE):
    """Open a Tink file in binary or text mode.

    The filename argument can be an actual filename (a str or bytes object), or
    an existing file object to read from or write to.

    The mode argument can be "r", "rb", "w", "wb", "x", "xb", "a" or "ab" for
    binary mode, or "rt", "wt", "xt" or "at" for text mode. The default mode is
    "rb".

    For binary mode, this function is equivalent to the TinkFile constructor:
    TinkFile(filename, mode, tink_key). In this case, the encoding, errors
    and newline arguments must not be provided.

    For text mode, a TinkFile object is created, and wrapped in an
    io.TextIOWrapper instance with the specified encoding, error handling
    behavior, and line ending(s).

    Encryption is done by chunks to reduce memory footprint. The default
    chunk_size is 64KB.
    """
    return _open_t(filename, mode=mode,
         encoding=encoding, errors=errors, newline=newline,
         chunk_size=chunk_size,
         cryptor='tink', tink_key=tink_key)
