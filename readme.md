# anonymous-tokens

A C#-implementation of https://github.com/tjesi/anonymous-tokens.

## Scope

This Proof-of-Concept contains:

- Generating the key pair
- Initiating the communication with random numbers
- Generating the token and creating the proof of correctness
- Randomizing the token and verifies proof of correctness
- Verification of token

## Future work

- Performance-pass
- Usage of `SecureRandom` - re-use vs instantiation per use
- Test-coverage

## Sources

- [Elliptical curve cryptography with Bouncy Castle](https://www.codeproject.com/Tips/1150485/Csharp-Elliptical-Curve-Cryptography-with-Bouncy-C)
