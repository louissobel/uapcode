import platform
import re
import inspect
import sys
import hashlib
import base64

import rsa

from requests.auth import AuthBase
from requests.utils import parse_dict_header
from requests.cookies import extract_cookies_to_jar

SIGNING_KEY_DATA = """
-----BEGIN RSA PRIVATE KEY-----
MIICYAIBAAKBgQCJ1Kx/47kLO1VAa2ZgpjjYsZQiEiCGNqPwxwSMYeJXutG5glnZ
E9pzKXWImnG3LwENGdcvx0ANqy635kWGkxMJCHWe1tOHVU9PUK7n4NbDR/tPuG0F
3XFmjOuZ+F4vJJg+3h2usZg3QQRLZpLvEXoPFsco4LecgqW2uAdKHWgWtwIDAQAB
AoGAGBBLdaCag/196ttVanZa4mpOhIxJpWUQxk7Y2nGUhOCXER5S9XVj5EtOu+TL
CcJpGpJyYWMWKczDQVQwoG3Ah6ufI8o6FKhyfh3Vd/cPEJN82ErL9b5/Cf03BX4s
iYOPm7olukPBaDLOPRjfJlokflKcjUf8tGi2fHI/qGc4+7ECRQCZzrODMKtUnSYI
9Yt3nbQMCgBWfXi1g5vkQcmhrdpj11fXmZCMk+P7BYhJHmb9X2q9xmuYdejmv9Vr
GDhHuQ/iCj4MLQI9AOVoexR2/h7ALGqXgzIbT4aGdWD3vlWR1Z/sDr3KJVIrYg6t
pkBpTI4CozCj1+NRMj7yEQCJg8ZCYLmo8wJELn3eoU862s7NynN+ft+6ptD3HS28
KRHpM2v3aNnGY9uZ/9+5Y+ToSt53PbLk6r3G5CpwJ5uslONzvXWKvZNhC7CQ5NkC
PQDYgWmfX8nnBaElnAailGnSYTWIJWgJZBAD1Qn4jj34tZ7ekX4UzgwE/nI7JnZK
P8g25cesBRxLUTvuHIcCRDRVggwaTJEo2MeRez4KbvUR0b/eKVq5TcMoligrY4qc
SFm3UW06IT+lxfW0KKkRuDDNxtXmbGQDUW7h7xenmjXaz8Is
-----END RSA PRIVATE KEY-----
"""


class TrustedComputingBase(object):

    def __init__(self):
        self.privatekey = rsa.PrivateKey.load_pkcs1(SIGNING_KEY_DATA)

    def get_attestation_and_signature(self, include_in_signature):
        """
        Attestation and signature
        """
        # Attestation is python build
        #attestation = platform.python_build()[0]
        # TODO(sobel) attestion is just 'python' right now
        attestation = 'python'
        message_to_sign = attestation + ":" + include_in_signature
        signature = rsa.sign(message_to_sign, self.privatekey, 'SHA-1')
        b64sig = base64.b64encode(signature)

        return attestation, b64sig

class HTTPAttestation(AuthBase):
    """
    Attatches HTTP Attestation logic
    """
    def __init__(self):
        self.chal = {}
        self.pos = None
        self.tcb = TrustedComputingBase()

    def get_extra_attestation(self):
        """
        extra attestation is just the SHA1
        of the contents of the __main__
        package. Janky, not really secure,
        but representative.

        returns b64encoded SHA1 digest
        """
        main = sys.modules['__main__']
        main_source = inspect.getsource(main)
        d = hashlib.sha1()
        d.update(main_source)
        return base64.b64encode(d.digest())

    def get_request_digest(self, prepared_request):
        """
        md5 of request body
        md5 because because.
        """
        d = hashlib.md5()
        d.update(prepared_request.method)
        d.update(":")
        d.update(prepared_request.path_url)
        d.update(":")
        if prepared_request.body:
            d.update(prepared_request.body)
        return d.hexdigest()

    def build_attestation_header(self, prepared_request):
        nonce = self.chal['nonce']
        extra_attestation = self.get_extra_attestation()
        request_digest = self.get_request_digest(prepared_request)

        include_in_signature = "%s:%s:%s" % (extra_attestation, nonce, request_digest)
        attestation, signature = self.tcb.get_attestation_and_signature(include_in_signature)
        return "%s:%s:%s:%s" % (attestation, extra_attestation, nonce, signature)

    def handle_421(self, r, **kwargs):
        """
        Given a response, if is 421 parses out the
        Attestation-Challenge header and tries again
        with an attestation. Will try once.
        """

        if self.pos is not None:
            # Rewind the file position indicator of the body to where
            # it was to resend the request.
            r.request.body.seek(self.pos)

        num_421_calls = getattr(self, 'num_421_calls', 1)
        attestation_challenge = r.headers.get('attestation-challenge', '')

        if r.status_code == 421 and num_421_calls < 2:
            setattr(self, 'num_421_calls', num_421_calls + 1)

            pat = re.compile(r'^attestation ', flags=re.IGNORECASE)
            self.chal = parse_dict_header(pat.sub('', attestation_challenge, count=1))

            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            r.content
            r.raw.release_conn()
            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep.headers['Attestation'] = self.build_attestation_header(prep)
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        setattr(self, 'num_421_calls', 1)
        return r

    def __call__(self, r):

        try:
            self.pos = r.body.tell()
        except AttributeError:
            pass

        r.register_hook('response', self.handle_421)
        return r
