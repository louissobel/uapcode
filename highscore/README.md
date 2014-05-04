Highscore
===========

Brings everything together.


It is a simple server that

 - serves a javascript game from a GET request, to anyone
 - accepts high scores for that game, __only from two trusted clients that must attest themselves__:
     - a POST request from the exact page that was served, made using
       the modified version of chromium
     - the included python client, which uses the modified requests library

