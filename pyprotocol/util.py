import hashlib
import inspect

def sha256(m):
    h = hashlib.sha256()
    h.update(m)
    return h.hexdigest()

def get_class_hash(klass):
    return sha256(inspect.getsource(klass))