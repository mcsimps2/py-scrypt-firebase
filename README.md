# pyscryptfirebase
PyPI: https://pypi.org/project/pyscryptfirebase/
A Python wrapper of Firebase's custom scrypt implementation.  A combined fork of scrypt and Firebase scrypt.

Firebase scrypt for password hashing: https://github.com/firebase/scrypt

Python library for scrypt: https://bitbucket.org/mhallin/py-scrypt/src/default/

Instructions
============
Note that if you have the Python module `scrypt` installed, you will need to remove it to use this library.
This library is a fork of `scrypt` and uses a modified C extension by the same name as `scrypt`.  Using both
libraries at the same time will cause a naming collision on the C module `_scrypt`.

Install dependencies according to your Python version and OS:
```
# Debian/Ubuntu
$ sudo apt-get install build-essential libssl-dev python-dev

# Fedora, RHEL
$ sudo yum install gcc openssl-devel python-devel

# Alpine Linux (Docker Containers)
$ apk add gcc openssl-dev python-dev

# (If you're on Python3, install the Python3 versions of the above packages)

# Mac
# Without setting the flags below, install will fail to find the necessary files
$ brew install openssl
$ export CFLAGS="-I$(brew --prefix openssl)/include $CFLAGS"
$ export LDFLAGS="-L$(brew --prefix openssl)/lib $LDFLAGS"
```

Then install `pyscriptfirebase`:
```
$ pip install pyscriptfirebase
```


Example
========
This module is intended to give the same output as the scrypt password hashing function that Firebase
uses.

Firebase Scrypt Utility example:
```
# Params from the project's password hash parameters
base64_signer_key="jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="
base64_salt_separator="Bw=="
rounds=8
memcost=14

# Params from the exported account
base64_salt="42xEC+ixf3L2lw=="

# The users raw text password
password="user1password"

# Generate the hash
# Expected output:
# lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==
echo `./scrypt "$base64_signer_key" "$base64_salt" "$base64_salt_separator" "$rounds" "$memcost" -P <<< "$password"`
```

`pyscryptfirebase` example:
```
import base64

import pyscryptfirebase


base64_signer_key = base64.b64decode("jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==")
base64_salt_separator = base64.b64decode("Bw==")
rounds = 8
memcost = 14

base64_salt = base64.b64decode("42xEC+ixf3L2lw==")
password = "user1password"

# Expected output:
# lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==
output = pyscryptfirebase.encrypt(
    base64_signer_key,
    base64_salt,
    base64_salt_separator,
    rounds,
    memcost,
    password
)
encoded_output = base64.b64encode(result)
print(encoded_output)
```

