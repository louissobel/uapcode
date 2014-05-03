"""
attestation manager
"""
import functools
import threading
import random
import hashlib
import base64

import rsa
import flask

from body_digest_middleware import BodyDigestMiddleware

NONCE_CHARS = list('0123456789abcdef')

class AttestationHandler(object):
    """
    Handles an attestation

    Needs to have

     - public_key_file - will be loaded
    """

    def __init__(self):
        with open(self.public_key_file, 'r') as f:
            self.public_key = rsa.PublicKey.load_pkcs1(f.read())

    def will_accept_signature(self, message, signature):
        try:
            bsig = base64.b64decode(signature)
        except TypeError:
            # Incorrect Padding
            return False

        try:
            rsa.verify(message, bsig, self.public_key)
        except rsa.pkcs1.VerificationError:
            return False
        else:
            return True

    def will_accept_attestation(self, attestation):
        raise NotImplementedError

    def will_accept_extra_attestation(self, attestation, extra_attestation, request):
        raise NotImplementedError

class AttestationManager(object):

    MESSAGE = "<h1>Attestation Required</h1>"

    def __init__(self, app):

        # Wrap it so we can access the body digest
        app.wsgi_app = BodyDigestMiddleware(app.wsgi_app)
        self.handlers = []
        self.nonce_store = NonceStore()

    def register_handler_class(self, handler_class):
        self.handlers.append(handler_class())
        return handler_class # so it can be a decorator

    def will_accept_nonce(self, nonce):
        return self.nonce_store.check_and_delete(nonce)

    ## Decorator for flask
    def attestation_required(self, function):

        @functools.wraps(function)
        def inner(*args, **kwargs):
            if self.is_attested(flask.request):
                return function(*args, **kwargs)
            else:
                r = flask.make_response(self.MESSAGE, 421)
                r.headers['Attestation-Challenge'] = self._get_attestation_challenge()
                return r
        return inner

    def is_attested(self, request):
        """
        returns true or false, attested or not
        """
        a = request.headers.get('attestation')
        if a is None:
            print "No Header!"
            return False

        v = a.split(':')
        if not len(v) == 4:
            return False

        print "attestation=%r,extra_attstation=%r,nonce=%r,signature=%r" % tuple(v)
        attestation, extra_attestation, nonce, signature = v

        # If it's not a valid nonce, reject outright
        if not self.will_accept_nonce(nonce):
            print "Nonce rejected %s" % nonce
            return False
        print "Nonce %s OK" % nonce

        # Then, I have to find a handler willing to accept this attestation
        found_handler = None
        for handler in self.handlers:
            if handler.will_accept_attestation(attestation):
                found_handler = handler
        handler = found_handler

        if handler is None:
            print "No handler accepted attestation %s" % attestation
            return False
        print "Handler accepted attestion %s: %s" % (attestation, handler.__class__.__name__)

        # The handler needs to accept the extra info as well
        # Pass it the request because why not.
        if not handler.will_accept_extra_attestation(attestation, extra_attestation, request):
            print "Handler rejected extra attestation %s" % extra_attestation
            return False
        print "Extra attestation %s accepted" % extra_attestation

        # Get body digest and signed message
        body_digest = self._get_body_digest(request)
        m = attestation + ':' + extra_attestation + ':' + nonce + ':' + body_digest

        # Now lets validate the signature.
        if not handler.will_accept_signature(m, signature):
            print "handler rejected signature %s for message %s" % (signature, m)
            return False
        print "Signature %r is OK" % signature

        # nonce, attestation, extra_attestation, signature
        # are all good. Lets let them in!
        return True

    def _get_body_digest(self, request):
        return request.environ['body_md5']

    def _get_attestation_challenge(self):
        nonce = self.nonce_store.get_new_nonce()
        return 'Attestation nonce="%s"' % nonce

class NonceStore(object):

    def __init__(self):
        self.available_nonces = set()
        self.lock = threading.Lock()

    def get_new_nonce(self):
        """
        Creates a nonce and stores it
        """
        nonce = self._generate_nonce()
        self.available_nonces.add(nonce)
        return nonce

    def check_and_delete(self, nonce):
        """
        atomically checks and deletes a nonce
        so will only ever return True ONCE
        """
        found = False
        with self.lock:
            if nonce in self.available_nonces:
                found = True
                self.available_nonces.remove(nonce)
        return found

    def _generate_nonce(self):
        """
        Not a crpyto PRNG!
        """
        return ''.join([random.choice(NONCE_CHARS) for i in range(32)])
