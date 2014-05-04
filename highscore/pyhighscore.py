"""
Python client to high score
"""
import sys
import random

import requests

import utils
utils.fix_up_pythonpath()
from requests_attestation import HTTPAttestation

SERVER_ADDRESS = 'http://localhost:9999'

class Round(object):

    def __init__(self):
        self.score = 0
        self.sofar = ''

    def run(self):
        """
        returns score
        """
        print "New Round!"
        alive = True
        while alive:
            print "Score: %d" % self.score
            if self.sofar:
                print "Sofar: %s" % self.sofar
            guess = self._get_guess()
            next = int(round(random.random()))
            if next == guess:
                print "Correct!"
                self.sofar += str(next)
                self.score += 1
            else:
                print "WRONG!"
                return self.score


    def _get_guess(self):
        while True:
            guess = raw_input("Is the next number 0 or 1? > ")
            if not guess in ('0', '1'):
                print "You must choose 0 or 1"
            else:
                return int(guess)

class Submit(object):

    def __init__(self, score):
        self.score = score

    def run(self):
        name = raw_input("Enter your name > ")
        r = requests.post(SERVER_ADDRESS, {
            'name': name,
            'score': self.score,
        }, auth=HTTPAttestation())
        r.raise_for_status()

class MultiRound(object):

    def run(self):
        print "The Number Guessing Game!"
        print "-=-=-=-=-=-=-=-=-=-=-=-=-"
        while True:
            score = Round().run()
            print
            print "%d is an alright score" % score
            wants_to_submit = self._get_wants_to_submit()
            if wants_to_submit:
                Submit(score).run()

    def _get_wants_to_submit(self):
        while True:
            guess = raw_input("Would you like to submit your score [y/n]? > ")
            if not guess in ('y', 'n'):
                print "You must choose y or n"
            else:
                return guess == 'y'


if __name__ == "__main__":
    print MultiRound().run()
