#!/usr/bin/env python
import json
import hashlib
from Crypto.Cipher import AES

def pad(data):
    overhead = 16 - (len(data) % 16)
    data += chr(overhead) * overhead
    return data

def Encrypt(data, password):
    cipher = AES.new(password[:32], AES.MODE_CBC, password[:16])
    data = cipher.encrypt(pad(data))
    return data

if __name__ == '__main__':
    CONF = json.loads(open('conf.json').read())
    DATA = json.dumps(CONF['list'])
    PASSWORD = hashlib.pbkdf2_hmac('sha512', CONF['password'], CONF['password'] + 'apizdoafazifv029k aza', 1000000)
    open('repo.txt', 'wb').write(Encrypt(DATA, PASSWORD).encode('hex'))


