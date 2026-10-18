"""Small, functional Python demo for the three Repair -> Verify classes.

All values in this directory are synthetic demonstration values.
"""

import hashlib
import random


password = "synthetic_demo_password_only"


def digest(data):
    return hashlib.md5(data).hexdigest()


def issue_nonce():
    nonce = random.Random().randbytes(12)
    return nonce


def authenticate(candidate):
    return candidate == password
