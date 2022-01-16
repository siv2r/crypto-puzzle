This is a challenge posted by [Elliot Jin](https://twitter.com/robot__dreams) on Twitter. Check out the detailed problem statement [here](https://gist.github.com/robot-dreams/669c13bc724fdeb9af8460c9b64d5665).

### Question
Find the private key. Given that nonce is reused for both the signatures below. The signatures and public key are BIP-340 compliant.

### Public Key
`463F9E1F3808CEDF5BB282427ECD1BFE8FC759BC6F65A42C90AA197EFC6F9F26`

### Message 1
`6368616E63656C6C6F72206F6E20746865206272696E6B206F66207365636F6E`
### Signature 1
`F3F148DBF94B1BCAEE1896306141F319729DCCA9451617D4B529EB22C2FB521A32A1DB8D2669A00AFE7BE97AF8C355CCF2B49B9938B9E451A5C231A45993D920`

### Message 2
`6974206D69676874206D616B652073656E7365206A75737420746F2067657420`
### Signature 2
`F3F148DBF94B1BCAEE1896306141F319729DCCA9451617D4B529EB22C2FB521A974240A9A9403996CA01A06A3BC8F0D7B71D87FB510E897FF3EC5BF347E5C5C1`

### My Solution
- signature1 = R.x || s1
- signature2 = R.x || s2
- s1 = r + tagged_hash(R.x || P.x || m1).x
  - let e1 = tagged_hash(R.x || P.x || m1)
- s2 = r + tagged_hash(R.x || P.x || m2).x
  - let e2 = tagged_hash(R.x || P.x || m2)
- Now, s1 - s2 = (e1 - e2).x 
- Therefore, x = (s1 - s2).(e1 - e2)^-1
- The calculated value of x is:
  - `636f6e67726174756c6174696f6e7320796f7520666f756e642074686520736b` (in hex)
  - congratulations you found the sk (in ascii)