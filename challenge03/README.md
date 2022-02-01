This is the third challenge posted by [Elliot Jin](https://twitter.com/robot__dreams) on Twitter. Check out the detailed problem statement [here](https://gist.github.com/robot-dreams/6300fde4017eefcf02c241f203a75162).

---

Problem Statement
---
The signer is using the following insecure scheme: whenever multiple signers with public keys `X1, ..., Xn` want to collaboratively sign a message, they proceed as follows:

- Generate private nonces `r1, ..., rn`
- Exchange all the corresponding public nonces `R1, ..., Rn`
- When generating the SHA256 challenge value:
	- Use `X = X1 + ... + Xn` as the aggregate public key
	- Use `R = R1 + ... + Rn` as the aggregate public nonce

Each signer generates partial signature `si = ri + H(X, R, m) * xi` (where `xi` is the i-th signer's private key). The the sum of all the partial signatures, together with the aggregate nonce `R`, is a valid Schnorr signature for the message `m` against the public key `X`.

This challenge is interactive, and involves making a test pass. You will find three files:

- `naive_multisig.py`: An implementation of the insecure multisignature scheme; you should in particular consult the `test_normal_multisig()` function for more details on how the scheme works
- `reference.py`: A naive and slow Python 3.7 implementation of BIP-340 (the version below was copied directly from the [version in the bips repo](https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py)). WARNING: Do not use this in production!
- `util.py`: A small collection of helper functions; you shouldn't need to edit these

Your task is to fill in the implementation of `forge_signature()` in `naive_multisig.py` to make `test_forgery()` pass. Good luck!

---

Solution
---
