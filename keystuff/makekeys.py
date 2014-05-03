"""
Will generate two keys, to tcb_key.cpp, tcpkey.pub
Private will be printed out in a format ready for
pasting into a Cpp file.

The public will be exported as PEM
"""
KEYSIZE = 1024

import base64
import os
import sys

import rsa

pub, pri = rsa.newkeys(1024)

with open('%s.private' % sys.argv[1], 'w') as f:
    f.write(pri.save_pkcs1())
    f.close()

with open('%s.public' % sys.argv[1], 'w') as f:
    f.write(pub.save_pkcs1())

