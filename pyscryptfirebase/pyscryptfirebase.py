#!/usr/bin/env python
# -*- coding: utf-8 -*-
import imp
import sys

from ctypes import (cdll,
                    c_char_p,
                    c_size_t, c_int, c_uint32,
                    create_string_buffer)

__version__ = '0.8.13'

_scrypt = cdll.LoadLibrary(imp.find_module('_scrypt')[1])

_scryptenc_buf_saltlen = _scrypt.exp_scryptenc_buf_saltlen
_scryptenc_buf_saltlen.argtypes = [c_char_p,  # const uint_t  *inbuf
                                   c_size_t,  # size_t         inbuflen
                                   c_char_p,  # uint8_t       *outbuf
                                   c_char_p,  # const uint8_t *passwd
                                   c_size_t,  # size_t         passwdlen
                                   c_char_p,  # const uint_t  *salt
                                   c_size_t,  # size_t         saltlen
                                   c_uint32,  # uint32_t       rounds
                                   c_uint32,  # uint32_t       memcost
                                   ]
_scryptenc_buf_saltlen.restype = c_int

ERROR_MESSAGES = ['success',
                  'getrlimit or sysctl(hw.usermem) failed',
                  'clock_getres or clock_gettime failed',
                  'error computing derived key',
                  'could not read salt from /dev/urandom',
                  'error in OpenSSL',
                  'malloc failed',
                  'data is not a valid scrypt-encrypted block',
                  'unrecognized scrypt format',
                  'decrypting file would take too much memory',
                  'decrypting file would take too long',
                  'password is incorrect',
                  'error writing output file',
                  'error reading input file']

MAXMEM_DEFAULT = 0
MAXMEMFRAC_DEFAULT = 0.5
MAXTIME_DEFAULT = 300.0
MAXTIME_DEFAULT_ENC = 5.0

IS_PY2 = sys.version_info < (3, 0, 0, 'final', 0)


class error(Exception):
    def __init__(self, scrypt_code):
        if isinstance(scrypt_code, int):
            self._scrypt_code = scrypt_code
            super(error, self).__init__(ERROR_MESSAGES[scrypt_code])
        else:
            self._scrypt_code = -1
            super(error, self).__init__(scrypt_code)


def _ensure_bytes(data):
    if IS_PY2 and isinstance(data, unicode):
        raise TypeError('can not encrypt/decrypt unicode objects')

    if not IS_PY2 and isinstance(data, str):
        return bytes(data, 'utf-8')

    return data


def encrypt(key, saltbase, saltsep, rounds, memcost, password):
    key = _ensure_bytes(key)
    saltbase = _ensure_bytes(saltbase)
    saltsep = _ensure_bytes(saltsep)
    total_salt = saltbase + saltsep
    password = _ensure_bytes(password)

    # outbuf = create_string_buffer(len(input) + 128)
    outbuf = create_string_buffer(len(key))
    # verbose is set to zero
    result = _scryptenc_buf_saltlen(key, len(key),
                                    outbuf,
                                    password, len(password),
                                    total_salt, len(total_salt),
                                    rounds, memcost)
    if result:
        raise error(result)

    return outbuf.raw


__all__ = ['error', 'encrypt']
