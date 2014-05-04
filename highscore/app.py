import hashlib
import os
import base64
import datetime

import flask

import utils
utils.fix_up_pythonpath()

from flask_attestation import AttestationHandler, AttestationManager

app = flask.Flask(__name__)
app.debug = True

attestation_manager = AttestationManager(app)

@attestation_manager.register_handler_class
class ChromeAttestationHandler(AttestationHandler):
    public_key_file = os.path.join(app.root_path, 'chrome.public')

    def will_accept_attestation(self, attestation):
        return attestation == 'chrome'

    def will_accept_extra_attestation(self, attestation, extra_attestation, request):
        if request.method == 'GET':
            # Then accept anything.
            return True
        elif request.method == 'POST':
            # Then check that included page is what is should be
            # (the result of the GET)
            #expected = hashlib.sha1(flask.render_template('game.html')).digest()
            expected = base64.b64encode(hashlib.sha1(flask.render_template('game.html')).digest())
            actual = base64.b64decode(extra_attestation)
            return expected == actual

scores = []

@app.route('/', methods=('GET',))
def serve_game():
    return flask.render_template('game.html')

@app.route('/scores')
def show_scores():
    sorted_scores = sorted(scores, key=lambda e : -e[1])
    return flask.render_template('scores.html', scores=sorted_scores)

@app.route('/', methods=('POST',))
@attestation_manager.attestation_required
def submit_high_score():
    name = flask.request.form['name']
    score = flask.request.form['score']
    scores.append((name, int(score), datetime.datetime.now().strftime("%c")))
    return flask.redirect('/scores')


if __name__ == "__main__":
    app.run('0.0.0.0', 9999)
