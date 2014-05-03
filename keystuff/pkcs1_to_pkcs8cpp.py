"""
Converts pkcs1 private key

to a cpp static uint array with name kSigningPrivateKey
"""
import sys
import os
import base64

privkey_file = sys.argv[1]
command = "openssl pkcs8 -topk8 -inform PEM -outform PEM -in %s -out %s.pkcs8  -nocrypt" % (privkey_file, privkey_file)
os.system(command)

content = open('%s.pkcs8' % privkey_file).read()

k = ''.join(content.split('\n')[1:-2])

priv_octets = ["0x%02x" % ord(c) for c in base64.b64decode(k)]

OCTET_PER_LINE = 8
octet_rows = []
for i in xrange(0, len(priv_octets), OCTET_PER_LINE):
  octet_rows.append(priv_octets[i:i+OCTET_PER_LINE])

print_rows = ['  ' + ', '.join(r) for r in octet_rows]
priv_body =  ',\n'.join(print_rows)

priv_head = "static const uint8 kSigningPrivateKey[] = {\n"
priv_foot = "\n};"

print priv_head + priv_body + priv_foot
