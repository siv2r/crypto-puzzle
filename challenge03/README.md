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
Build Instructions
---
Move to the root folder of the project
```
cd ./challenge03
python3 ./naive_multisig.py
```
---

Solution
---
1. Create a pubkey list as `[X1, X2']`. Here, `X2' = X2 - X1`
   1. Therefore, `agg([X1, X2'])` = `X1 + X2'` = `X1 + (X2 - X1)` = `X2`
   2. This will allow the owner of pubkey `X2` to steal the funds
   3. ***Note:*** 1) `y(X2')` should be even. 2) `y(X2)` should be even --> confirm point 2 once
   4. The `schnorr_verify` and `x_only_agg` functions implictly assume `y` to be even
   5. we tranfer pubkey in x-only form so, it doesn't have info about `y`. Hence, we want `y(X2') = even`.
2. Sign the given message using `schnorr_sign` with `X2`
3. Now, you are ready to steal the funds!

---

Notes
---
*BIP-340 impl notes*
EC point is stored as int tuple so, need to convert it to bytes
bytes are converted to int for scalar arithmetic

*BIP-340 function notes*
1. `pubkey_gen`        -> returns a 32 bytes array, x-coordinate of generated pubkey (y = even or odd)
2. `int_from_bytes`    -> int from the given big endian byte array
3. `bytes_from_int`    -> 32 bytes array from int
4. `bytes_from_point`  -> 32 byte array of x-coordinate of the EC Point
5. `tagged_hash`       -> hash the given msg according to BIP-340
6. `lift_x`            -> generates (x, y) EC point for the given x (in bytes). Here, y = even

*Util function notes*
1. `cbytes_from_point` -> compressed 33 byte array EC Point (0x02 = even y, 0x03 = odd y)
2. `point_from_cbytes` -> creates EC Point from the given compressed EC Point. Point = ECDSA pubkey
3. `xonly_point_agg`   -> return (x, y) EC point addition result for x-only points input array
4. In `x_only_int` function, the condition `if has_even_y(point_mul(G,k)) != has_even_y(P_agg):`  
 ***Note:*** the above condt is a nicer way of writing the following condt.
```python
 if not has_even_y(point_mul(G, k)): # since, nonce aggregation assumes all y(Ri) = even
    k = n - k
 if not has_even_y(P_agg): # since, verify uses lift_x() which always results in y(P_agg or R_agg) = even
    k = n - k
```
---

Doubts
---
Q: why is "inf" the identity elem? why not the point (0, 0)?
Ans: (0, 0) does not lie on the EC `y^2 = x^3 + 7`

Q: does the co-signer's pubkey need to have even y?
Ans: No, it is not necessary. During the generation of partial signature, the co-signer's private key will be adjusted (`k` -> `n-k`) if their pubkey possed an odd y. 
This is highly dependent on the implementation of the multisignature algorithm.

Q: during calculation of aggregate nonce and pubkeys
   can `y(Xagg)` be odd? should the aggregate pubkey key be have an even y?
   - yes, since, if we allow odd y values the schnorr_verify will fail 
   - since, it assume y = even implicitly. 
   - Also, during the transferring pukey btw function we use x-only pubkey form 
   - so, it has no info about `y(Xagg)`

Q: In prev question, what to do if Xagg is odd?
   - everyone will have your pubkey so, you shouldn't modify its value
   - for this reason during schnorr_sign, you make `x = n - x` (changing priv key for signature)
   - since, schnorr_verify uses `lift(x)` which always produces even y points

Q: In schnorr_verify function (line 141), why not R == point_mul(G, r)?
Q: does python support arithmetic on bytes?
Q: is it necessary for bytes-> int conversion here? can't python add two bytes (not concat)?

---
