import rsa

from user_agent import *
from server import Server
from tpm import TPM

def main(UAClass):
    print "Running Protocol with %s" % UAClass.__name__
    print "=" * 40
    publickey, privatekey = rsa.newkeys(512)
    tpm = TPM(privatekey)
    ua = UAClass(tpm)
    server = Server(publickey)
    ua.send_message("Javascript result", server)

if __name__ == "__main__":
    main(TrustedUserAgent)
    print
    main(UnTrustedUserAgent)