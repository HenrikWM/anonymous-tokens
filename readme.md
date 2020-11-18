# anonymous-tokens

A C#-implementation of <https://github.com/tjesi/anonymous-tokens>.

## Scope

This Proof-of-Concept contains:

- Generating the key pair
- Initiating the communication with random numbers
- Generating the token and creating the proof of correctness
- Randomizing the token and verifies proof of correctness
- Verification of token

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
  - `dotnet run --project .\samples\ClientServer\Client\Client.Console\Client.Console.csproj`
  - `dotnet run --project .\samples\ClientServer\Server\Server.TokenGeneration.Api\Server.TokenGeneration.Api.csproj`
  - `dotnet run --project .\samples\ClientServer\Server\Server.TokenVerification.Api\Server.TokenVerification.Api.csproj`

## Roadmap

- Test-coverage
- Performance-pass
- Investigate usage of `SecureRandom` - re-use vs instantiation per use
- Publish NuGet-package

## Sources

- [Elliptical curve cryptography with Bouncy Castle](https://www.codeproject.com/Tips/1150485/Csharp-Elliptical-Curve-Cryptography-with-Bouncy-C)
