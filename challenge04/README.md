This is the fourth challenge posted by [Elliot Jin](https://twitter.com/robot__dreams) on Twitter. Check out the detailed problem statement [here](https://gist.github.com/robot-dreams/055f158466950dc37821b73d887e8a54).

---

Given the following shares of a secret that was split using Shamir's Secret Sharing, can you recover the secret?
```
(1, 0xB4EB3F62388EA2343FFC28BB342D4245E9C8B3B0602825235460DD74F0D47AB1)
(3, 0xBE3A9EC4C3D5FA291CAFBB54C5F0301F29FE14539575408B57F3CF6C0EA6399E)
(4, 0x760E31377BF2240AD9DA8A9843FF4B27A0D42F66DF029BF06A8F584FA008EA4D)
```
You may want to check your work by encoding the final result as a 32-byte big-endian integer, and then interpreting the bytes as an ASCII string.

Build Instructions
---
1. Install sage on your system
   - For ubuntu, `sudo apt install sagemath`
   - Other systems, check the [documentation](https://doc.sagemath.org/html/en/tutorial/introduction.html#installation)
   - If you are using VS Code, you can tell it to associate `.sage` files to python for syntax highlighting (see this [stackoverflow thread](https://stackoverflow.com/questions/56318116/how-do-you-get-the-python-colour-scheme-while-using-sage-on-vs-code)).
2. `cd challenge04`, move into the challenge04 directory
3. run `sage` on terminal, this will open the sage interpreter
4. run `load("main.sage")`

Solution
---
Steps to recover secret from the given shares:
   - construct a `k-1` degree polynomial from `k` given points
   - use lagrange interpolation technique
   - evaluate the constructed polynomial at `x = 0`
   - Congrats, you recovered the secret!

For detailed explanation, checkout [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

