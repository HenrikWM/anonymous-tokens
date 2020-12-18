# anonymous-tokens

A C#-implementation of <https://github.com/tjesi/anonymous-tokens>.

## Getting started

A typical scenario consists of a client and a server. A complete sample of this scenario is available in the `samples\ClientServer` folder, where the client is a console application and the server is an ASP.NET MVC API.

1. Create a cryptographic key pair.

Example using the elliptic curve `prime256v1`:

```bash
# generate a private key for a curve
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

# generate corresponding public key
openssl ec -in private-key.pem -pubout -out public-key.pem
```

### Server

2. The server instantiates `TokenGenerator` and `TokenVerifier` so that they are available to the client.

If your `TokenGenerator` and `TokenVerifier` are hosted in a REST API you will need to create API-endpoints for token generation and verification. See the sample `Server.Token.Api` project for examples on request/response models, API-endpoint contract etc.

3. Create an implementation for `IPrivateKeyStore`.

We provide an `InMemoryPrivateKeyStore` which loads a dummy-key to use for demo purposes and quickstarts. Your **Private key** should be loaded from a database, embedded resource, from device storage etc.

4. Create an implementation for `ISeedStore`.

We provide an `InMemorySeedStore` which contains an in-memory list to use for demo purposes and quickstarts. Your seed store should be a database or some persistent storage.

### Client

5. Create an implementation for `IPublicKeyStore`.

We provide an `InMemoryPublicKeyStore` which loads a dummy-key to use for demo purposes and quickstarts. Your **Public key** should be loaded from a database, embedded resource, from device storage, loaded from an API etc.

6. Instantiate the `Initiate` class and perform token generation and token verification.

Here's an example from the sample `Console.Client` project on how this might look:

```csharp
// Import parameters for the elliptic curve prime256v1
var ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);

var publicKeyStore = new InMemoryPublicKeyStore();
var publicKey = await publicKeyStore.GetAsync();

_initiator = new Initiator();

// 1. Initiate communication with a masked point P = r*T = r*Hash(t)
var init = _initiator.Initiate(ecParameters.Curve);
var t = init.t;
var r = init.r;
var P = init.P;

// 2. Generate token Q = k*P and proof (c,z) of correctness
var (Q, proofC, proofZ) = await _tokenApiClient.GenerateTokenAsync(ecParameters.Curve, P);

// 3. Randomise the token Q, by removing the mask r: W = (1/r)*Q = k*T. Also checks that proof (c,z) is correct.
var W = _initiator.RandomiseToken(ecParameters, publicKey, P, Q, proofC, proofZ, r);

// 4. Verify that the token (t,W) is correct.
var isVerified = await _tokenApiClient.VerifyTokenAsync(t, W);
if (isVerified)
{
    Console.WriteLine("Token is valid.");
}
else
{
    Console.WriteLine("Token is invalid.");
}
```

Your client should now be able to perform the protocol flow.

## How to build

- [Install](https://www.microsoft.com/net/download/core#/current) the latest .NET Core 3.1 SDK
- Install Git
- Clone this repo

### Build & run with Visual Studio

- Open `AnonymousTokens.sln` in Visual Studio
- In Visual Studio right-click on the solution **AnonymousTokens** in the Solution Explorer window and choose **Set startup projects...**
- Select **Multiple startup projects** and set **Action** to **Start** on projects:
  - Client.Console
  - Server.TokenGeneration.Api
  - Server.TokenVerification.Api
- Build & run using F5 in Visual Studio

### Build & run with a terminal

- In the root of the cloned repo open 3 terminal windows.
- Run each in a separate terminal:
  - `dotnet run --project .\samples\ClientServer\Client.Console\Client.Console.csproj`
  - `dotnet run --project .\samples\ClientServer\Server.Token.Api\Server.Token.Api.csproj`

### Build and run benchmarks

After running `build.ps1` navigate to the benchmark project:

`cd test\AnonymousTokens.Benchmark`

Run all benchmarks:

`dotnet run -c Release --filter *`

When complete you will see the output generated in a new `BenchmarkDotNet.Artifacts\results` folder.

## Sources

- [Elliptical curve cryptography with Bouncy Castle](https://www.codeproject.com/Tips/1150485/Csharp-Elliptical-Curve-Cryptography-with-Bouncy-C)

### Suggested descriptive variable names

This code is naming variables according to the mathematics in the original crypographic work. The list below provides some programmer-friendly suggestions to what you could call these variables in your own code.

```
k privateKey
K publicKey
t tokenSeed
r tokenMask
P maskedPoint
Q signedPoint
c proofChallenge
z proofResponse
W submittedPoint
```

