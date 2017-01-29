import hmac
import hashlib
import random
from string import letters


secret = 'thisisasecretmessage'

def make_secure_val(val):
    """Return val and hashed val using hmac"""
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    """Check if val and hased result match"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Hash the users' passwords and check if matched in user authentication.
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)
