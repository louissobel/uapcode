import util

class TrustedUserAgent(object):
    """
    The user agent
    """
    def __init__(self, tpm):
        self.tpm = tpm

    def get_nonce(self, server):
        """
        stub for subclasses
        """
        print "UA: Asking server for nonce"
        nonce = server.get_nonce()
        print "UA: Got nonce %d" % nonce
        return nonce

    def send_to_server(self, server, message, auth_message, signature):
        print "UA: sending payload to server"
        response = server.process(message, auth_message, signature)
        print "UA: got response: %s" % response

    def send_message(self, message, server):
        """
        sends a message to the server
        """
        print "UA: I want to send %r to server" % message

        nonce = self.get_nonce(server)
        message_hash = util.sha256(message)

        print "UA: generating sha256 of message %r: %s" % (message, message_hash)

        print "UA: asking TPM for attestation of me with additional info (%s, %d)" % (message_hash, nonce)
        auth_message, signature = self.tpm.attest(self, message_hash, nonce)
        print "UA: got auth_message and signature"

        self.send_to_server(server, message, auth_message, signature)


class UnTrustedUserAgent(TrustedUserAgent):
    """
    Modified version, not in trust hash. Will be rejected
    """
    def send_message(self, message, server):
        return TrustedUserAgent.send_message(self, "Evil " + message, server)
