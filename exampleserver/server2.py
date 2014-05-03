import random
import base64
import hashlib

import flask
import rsa


app = flask.Flask(__name__)
app.debug = True

chars = list('0123456789abcdef')
get_rrealm = lambda : ''.join([random.choice(chars) for _ in range(6)])

KEY_FILE = 'tcb_key.pub'
with open(KEY_FILE) as f:
    keydata = f.read()
pubkey = rsa.PublicKey.load_pkcs1(keydata)

class RealmHolder(object):
    def __init__(self):
        self.r = get_rrealm()

    def next(self):
        self.r = get_rrealm()
        print "Next: %s" % self.r

rh = RealmHolder()

FORM = """
<div>
<form action="" method="POST">
<input type="hidden" name="foobar" value="hehaw" />
<input type="submit" value="submit" />
</form>
</div>
"""

def is_authorized():
    a = flask.request.headers.get('authorization')
    if a is None:
        return False

    u, p = base64.b64decode(a.split(' ')[1]).split(':')
    return u == 'sobel' and p == rh.r

@app.route('/', methods=('GET', 'POST'))
def index():
    authorized = is_authorized()
    if authorized:
        rh.next()
        return ("<h1>YAY!</h1><h2>%s</h2>" % rh.r) + FORM
    else:
        response = flask.make_response('', 401)
        response.headers['www-authenticate'] = 'basic realm="%s"' % rh.r
        return response


def attestation_ok(attestation):
    #TODO
    return attestation == 'chrome'

def verify_signature(m, sig):
    bsig = base64.b64decode(sig)
    try:
        rsa.verify(m, bsig, pubkey)
    except rsa.pkcs1.VerificationError:
        return False
    else:
        return True

def is_attested():
    a = flask.request.headers.get('attestation')
    if a is None:
        return False

    v = a.split(':')
    print "attestation=%r,extra_attstation=%r,nonce=%r,signature=%r" % tuple(v)
    attestation, extra_attestation, nonce, signature = v

    bd = hashlib.md5()
    bd.update(flask.request.environ['body_copy'])
    body_digest = bd.hexdigest()

    m = attestation + ':' + extra_attestation + ':' + nonce + ':' + body_digest
    print "m for verification: %r" % m

    if verify_signature(m, signature):
        print "Signature %r is OK" % signature
        if attestation_ok(attestation):
            print "Attestation %r OK" % attestation

            return nonce == rh.r
        else:
            print "Attestation %r is not OK" % attestation
            return False
    else:
        print "Signature %r is not OK" % signature 

@app.route('/attest', methods=('GET', 'POST'))
def attest():
    attested = is_attested()
    if attested:
        rh.next()
        return ("<h1>Attested</h1><h2>%s</h2>" % rh.r) + FORM
    else:
        response = flask.make_response('', 421)
        response.headers['attestation-challenge'] = 'attestation nonce="%s"' % rh.r
        return response

@app.route('/nochallenge', methods=('GET', 'POST'))
def nochallenge():
    print flask.request.environ['body_copy']
    return FORM

# Copied from
# http://stackoverflow.com/questions/10999990/get-raw-post-body-in-python-flask-regardless-of-content-type-header
class WSGICopyBody(object):
    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):

        from cStringIO import StringIO
        length = environ.get('CONTENT_LENGTH', '0')
        length = 0 if length == '' else int(length)

        body = environ['wsgi.input'].read(length)
        environ['body_copy'] = body
        environ['wsgi.input'] = StringIO(body)

        # Call the wrapped application
        app_iter = self.application(environ, 
                                    self._sr_callback(start_response))

        # Return modified response
        return app_iter

    def _sr_callback(self, start_response):
        def callback(status, headers, exc_info=None):

            # Call upstream start_response
            start_response(status, headers, exc_info)
        return callback


if __name__ == "__main__":
    app.wsgi_app = WSGICopyBody(app.wsgi_app)
    app.run('0.0.0.0', port=6999)
