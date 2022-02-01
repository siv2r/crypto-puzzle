import secrets

from reference import *
from util import *

def forge_signature(honest_signer, msg):
    """
    TODO: Your implementation here!
    Your goal is to return a tuple with two elements:
        - A list of public keys, at least one of which is the
          honest signer's public key
        - A valid BIP-340 signature for the input msg, when verified
          against the aggregate public key which is the sum of the
          individual public keys in the above list
    In trying to generate a forgery, you may interact with the
    honest signer by calling public methods as much as you want;
    however, to make this attack realistic, you're NOT allowed to:
        - Access private fields of the honest signer
        - Ask the honest signer to generate a partial signature
          on the same (pubkeys, msg) pair as the forgery you
          output
    Hopefully these restrictions are obvious and sensible; otherwise
    the challenge would be trivial.
    Good luck!
    """
    malicious_signer = NaiveMultisigSigner()
    X_hon = honest_signer.get_pubkey()
    X_mal = malicious_signer.get_pubkey()

    # X_mal_new = negate X_hon + X_mal
    # negate X_hon = y -> p-y
    # return [X_hon, X_mal_new]
    X_hon_point, X_mal_point = lift_x(X_hon), lift_x(X_mal)
    X_hon_neg_point = (X_hon_point[0], p - X_hon_point[1])
    X_mal_new_point = point_add(X_mal_point, X_hon_neg_point)
    X_mal_new = bytes_from_point(X_mal_new_point)

    X = [X_hon, X_mal_new] #pubkey list
    # get nonce commitment of honest signer ---> Interactive Round 1
    # now send your nonce commitment as R_mal_new = negate(R_hon) + R_mal
    R_hon = honest_signer.gen_partial_pubnonce()
    R_mal = malicious_signer.gen_partial_pubnonce()
    R_hon_point, R_mal_point = lift_x(R_hon), lift_x(R_mal)
    R_hon_neg_point = (R_hon_point[0], p - R_hon_point[1])
    R_mal_new_point = point_add(R_mal_point, R_hon_neg_point)
    R_mal_new = bytes_from_point(R_mal_new_point)

    R = xonly_point_agg([R_hon, R_mal_new])
    aggnonce = cbytes_from_point(R)

    # get partial signature of honest signer ----> Interactive Round 2
    # now send your partial signature as s_mal_new = s_mal + neg(s_hon)
    #TODO: is it necessary for bytes-> int conversion here? can't python add two bytes (not concat)?
    s_hon = honest_signer.gen_partial_sig(X, aggnonce, msg)
    s_mal = malicious_signer.gen_partial_sig(X, aggnonce, msg)
    temp = (int_from_bytes(s_mal) - int_from_bytes(s_hon)) % n
    s_mal_new = bytes_from_int(temp)

    sig = bytes_from_point(R) + partial_sig_agg([s_hon, s_mal_new])


    # verification
    # (R, s_agg)
    # c = H(X, R, msg)
    # G * (s_mal_new + s_hon) ?= R + c * X
    # G * (s_mal) ?= R + c * X => returns true since, R and X have been modified
    return X, sig
# BIP-340 impl notes
# EC point is stored as int tuple so, need to convert it to bytes
# bytes are converted to int for scalar arithmetic
#TODO: why is "inf" the identity elem? why not the point (0, 0)?
#TODO: does python support arithmetic on bytes?

# BIP-340 function notes
# 1. pubkey_gen        -> returns a 32 bytes array, x-coordinate of generated pubkey (y = even or odd)
# 2. int_from_bytes    -> int from the given big endian byte array
# 3. bytes_from_int    -> 32 bytes array from int
# 4. bytes_from_point  -> 32 byte array of x-coordinate of the EC Point
# 5. tagged_hash       -> hash the given msg according to BIP-340
# 6. lift_x            -> generates (x, y) EC point for the given x (in bytes). Here, y = even

# Util function notes
# 1. cbytes_from_point -> compressed 33 byte array EC Point (0x02 = even y, 0x03 = odd y)
# 2. point_from_cbytes -> creates EC Point from the given compressed EC Point. Point = ECDSA pubkey
# 3. xonly_point_agg   -> return (x, y) EC point addition result for x-only points input array

class NaiveMultisigSigner:
    def __init__(self, seckey=None):
        if seckey is None:
            seckey = secrets.token_bytes(32)
        self.seckey = seckey
        self.pubkey = pubkey_gen(self.seckey) # pubkey_gen returns 32 bytes x-only pubkey
        self.seen_queries = set()

    def get_pubkey(self):
        return self.pubkey

    # generates (nonce, nonce commitment) pair
    def gen_partial_pubnonce(self):
        self.secnonce = secrets.token_bytes(32)
        return pubkey_gen(self.secnonce)

    def gen_partial_sig(self, pubkeys, aggnonce, msg):
        assert pubkey_gen(self.seckey) in pubkeys
        assert len(aggnonce) == 33
        assert len(msg) == 32

        #calc aggregate nonce and pubkeys
        #NOTE: agg X or R may have odd y
        #TODO: can y(X) be odd? should the aggregate key be a schnorr pubkey (even y)? 
        X = xonly_point_agg(pubkeys)
        R = point_from_cbytes(aggnonce)
        r1 = xonly_int(self.secnonce, R)
        x1 = xonly_int(self.seckey, X)
        agg_pubkey = bytes_from_point(X)
        e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + agg_pubkey + msg)) % n

        self.seen_queries.add((agg_pubkey, msg))
        return bytes_from_int((r1 + e * x1) % n)

def test_normal_multisig():
    signer1 = NaiveMultisigSigner()
    signer2 = NaiveMultisigSigner()

    X1 = signer1.get_pubkey()
    X2 = signer2.get_pubkey()
    pubkeys = [X1, X2]
    agg_pubkey = bytes_from_point(xonly_point_agg(pubkeys))

    R1 = signer1.gen_partial_pubnonce()
    R2 = signer2.gen_partial_pubnonce()
    R = xonly_point_agg([R1, R2]) # why no `bytes_from_point()` func?
    msg = b'msg signed by both Alice and Bob'

    aggnonce = cbytes_from_point(R) # cbytes_from_point() vs bytes_from_point()?
    s1 = signer1.gen_partial_sig(pubkeys, aggnonce, msg)
    s2 = signer2.gen_partial_sig(pubkeys, aggnonce, msg)
    sig = bytes_from_point(R) + partial_sig_agg([s1, s2])

    # assert (agg_pubkey, msg) not in signer1.seen_queries ----> remove these
    # assert (agg_pubkey, msg) not in signer2.seen_queries
    assert schnorr_verify(msg, agg_pubkey, sig)

def test_forgery():
    honest_signer = NaiveMultisigSigner()
    msg = b'send all of Bob\'s coins to Alice'

    pubkeys, sig = forge_signature(honest_signer, msg)
    agg_pubkey = bytes_from_point(xonly_point_agg(pubkeys))

    assert honest_signer.get_pubkey() in pubkeys
    assert (agg_pubkey, msg) not in honest_signer.seen_queries
    assert schnorr_verify(msg, agg_pubkey, sig)
    print("Congrats!")

if __name__ == '__main__':
    test_normal_multisig()
    test_forgery()