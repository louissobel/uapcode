import inspect
import base64

import rsa

import util

class TPM(object):
    
    def __init__(self, privatekey):
        self.privatekey = privatekey
        print "TP: created with private key: %s" % privatekey

    def attest(self, attestor, *extra):
        """
        gets signed source code of attestor
        """
        print "TP: received attestation request from: %r" % attestor
        source_hash = util.get_class_hash(attestor.__class__)
        print "TP: got hash of source code of attestor: %s" % source_hash
        message = ','.join([source_hash] + [str(e) for e in extra])
        print "TP: signing message: %s" % message
        signature = base64.b64encode(rsa.sign(message, self.privatekey, 'SHA-256'))
        print "TP: got base64 signature: %s" % signature
        return message, signature
    