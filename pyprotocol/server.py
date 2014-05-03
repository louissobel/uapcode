import base64

import rsa

from user_agent import *
import util

class Server(object):

    def __init__(self, publickey):
        self.outstanding_nonces = set()

        self.trusted_useragent_attestations = {
            util.get_class_hash(TrustedUserAgent) : 'Trusted UserAgent Class'
        }

        # The public key of the TPM.
        self.publickey = publickey
        print "SE: created with TPM public key: %s" % publickey

    def get_nonce(self):
        print "SE: got Nonce request"
        nonce = rsa.randnum.randint(2**64)
        self.outstanding_nonces.add(nonce)
        print "SE: registering and returning nonce %d" % nonce
        return nonce

    def process(self, message, auth_message, signature):
        """
        checks then processes
        """
        attestation, message_hash, nonce_string = auth_message.split(',')
        nonce = long(nonce_string)

        # First assert the signature.
        if not rsa.verify(auth_message, base64.b64decode(signature), self.publickey):
            return "Error: Bad signature"
        else:
            print "SE: Signature OK"

        # Assert that nonce is one we are expecting, clearing it if so.
        if not nonce in self.outstanding_nonces:
            return "Error: Unrecognize nonce (%d)" % nonce
        else:
            self.outstanding_nonces.remove(nonce)
            print "SE: Nonce OK"

        # Assert that this user agent is a trusted one.
        if not attestation in self.trusted_useragent_attestations:
            return "Error: Untrusted UserAgent (%s)" % attestation
        else:
            print "SE: dealing with trusted user agent: %s" % self.trusted_useragent_attestations[attestation]

        # OK, last step, assert that the message was not tampered with.
        received_message_hash = util.sha256(message)
        if not received_message_hash == message_hash:
            return "Error: Message Hash does not match"
        else:
            print "SE: Message validated, sending to processing"

        # Great! process it.
        return "OK: %s" % ''.join(reversed(message))
    