from StringIO import StringIO
import hashlib

# In the spirit of
# http://stackoverflow.com/questions/10999990/get-raw-post-body-in-python-flask-regardless-of-content-type-header
class RequestDigestMiddleware(object):
    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        length = environ.get('CONTENT_LENGTH', '0')
        length = 0 if length == '' else int(length)

        body = environ['wsgi.input'].read(length)
        environ['wsgi.input'] = StringIO(body)

        # TODO: ideally, we'd read bits of the body
        # at a time so that it doesn't all have to 
        # go into memory. But for now, whatever.
        method = environ['REQUEST_METHOD']
        path = environ['PATH_INFO']
        if environ.get('QUERY_STRING'):
            path += '?' + environ['QUERY_STRING']

        h = hashlib.md5()
        h.update(method)
        h.update(':')
        h.update(path)
        h.update(':')
        h.update(body)
        environ['request_md5'] = h.hexdigest()

        # Call the wrapped application
        app_iter = self.application(environ, self._sr(start_response))

        # Return modified response
        return app_iter

    def _sr(self, start_response):
        def callback(status, headers, exc_info=None):

            # Call upstream start_response
            start_response(status, headers, exc_info)
        return callback