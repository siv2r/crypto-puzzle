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
    return None, None

class NaiveMultisigSigner:
    def __init__(self, seckey=None):
        if seckey is None:
            seckey = secrets.token_bytes(32)
        self.seckey = seckey
        self.pubkey = pubkey_gen(self.seckey)
        self.seen_queries = set()

    def get_pubkey(self):
        return self.pubkey

    def gen_partial_pubnonce(self):
        self.secnonce = secrets.token_bytes(32)
        return pubkey_gen(self.secnonce)

    def gen_partial_sig(self, pubkeys, aggnonce, msg):
        assert pubkey_gen(self.seckey) in pubkeys
        assert len(aggnonce) == 33
        assert len(msg) == 32

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
    R = xonly_point_agg([R1, R2])
    msg = b'msg signed by both Alice and Bob'

    aggnonce = cbytes_from_point(R)
    s1 = signer1.gen_partial_sig(pubkeys, aggnonce, msg)
    s2 = signer2.gen_partial_sig(pubkeys, aggnonce, msg)
    sig = bytes_from_point(R) + partial_sig_agg([s1, s2])

    assert schnorr_verify(msg, agg_pubkey, sig)

def test_forgery():
    honest_signer = NaiveMultisigSigner()
    msg = b'send all of Bob\'s coins to Alice'

    pubkeys, sig = forge_signature(honest_signer, msg)
    agg_pubkey = bytes_from_point(xonly_point_agg(pubkeys))

    assert honest_signer.get_pubkey() in pubkeys
    assert (agg_pubkey, msg) not in honest_signer.seen_queries
    assert schnorr_verify(msg, agg_pubkey, sig)

if __name__ == '__main__':
    test_normal_multisig()
    test_forgery()