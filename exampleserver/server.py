import BaseHTTPServer
import base64
import random

chars = list('0123456789abcdef')
get_rrealm = lambda : ''.join([random.choice(chars) for _ in range(6)]) 

class RealmHolder(object):
    def __init__(self):
        self.r = get_rrealm()

    def next(self):
        self.r = get_rrealm()

rh = RealmHolder()

FORM = """
<div>
<form action="" method="POST">
<input type="hidden" name="foobar" value="hehaw" />
<input type="submit" value="submit" />
</form>
</div>
"""

class AttestationDemandingRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'

    def __init__(self, *args, **kwargs):
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def challenge(self, which):
        if which == 'basic':
            code = 401
            st = 'Unauthorized'
            in_header = 'Authorization'
            out_header = 'www-authenticate'
            extra = 'basic realm="%s"' % rh.r
        elif which == 'attest':
            code = 401
            st = 'Unauthorized'
            in_header = 'Authorization'
            out_header = 'www-authenticate'
            extra = 'attestation realm="%s"' % rh.r

        auth = self.headers.get(in_header)
        if auth is None:
            rh.next()
            print "next: %s" % rh.r
            self.send_response(code, st)
            self.send_header('content-length', 0)
            self.send_header(out_header, extra)
            self.end_headers()
        else:
            u, p = base64.b64decode(auth.split(' ')[1]).split(':')
            if u == 'sobel' and p == rh.r:
                rh.next()
                self.send_response(200)
                m = ("<h1>YAY!</h1><h2>%s</h2>" % rh.r) + FORM
                self.send_header('content-length', len(m))
                self.end_headers()
                self.wfile.write(m)
            else:
                self.send_response(code, st)
                self.send_header('content-length', 0)
                self.send_header(out_header, extra)
                self.end_headers()

    def read_request(self):
        cl = self.headers.get('content-length')
        print cl, type(cl)

    def do_GET(self):
        r = self.read_request()
        if self.path == '/attest':
            self.challenge('attest')
        else:
            self.challenge('basic')

    do_POST = do_GET

def run():
    server_address = ('', 6999)
    handler_class = AttestationDemandingRequestHandler
    httpd = BaseHTTPServer.HTTPServer(server_address, handler_class)
    httpd.serve_forever()


if __name__ == "__main__":
    run()
    