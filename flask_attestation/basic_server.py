import flask

app = flask.Flask(__name__)
app.debug = True

PORT = 7001

PAGE = """
<div>
<h1>HI</h1>
<form action="" method="POST">
<input type="hidden" name="x" value="1" />
<input type="submit" value="submit" />
</form>
</div>
"""

import attestation

attestation_manager = attestation.AttestationManager(app)

@attestation_manager.register_handler_class
class PythonAttestationHandler(attestation.AttestationHandler):
    public_key_file = 'requests.public'

    def will_accept_attestation(self, attestation):
        return attestation == 'python'

    def will_accept_extra_attestation(self, attestation, extra_attestation, request):
        return True


@attestation_manager.register_handler_class
class ChromeAttestationHandler(attestation.AttestationHandler):
    public_key_file = 'chrome.public'

    def will_accept_attestation(self, attestation):
        return attestation == 'chrome'

    def will_accept_extra_attestation(self, attestation, extra_attestation, request):
        return True


@app.route('/', methods=('GET', 'POST'))
@attestation_manager.attestation_required
def index():
    return PAGE


if __name__ == "__main__":
    app.run('0.0.0.0', PORT)