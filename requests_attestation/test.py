import requests

from attestation import HTTPAttestation

print "Post.."
r = requests.post('http://localhost:7001/', auth=HTTPAttestation(), data={'foo':'bar'})
print r.status_code

print "Get.."
r = requests.get('http://localhost:7001/', auth=HTTPAttestation())
print r.status_code


print "Get.."
r = requests.get('http://localhost:7001/?bloopbloop=bap', auth=HTTPAttestation())
print r.status_code
