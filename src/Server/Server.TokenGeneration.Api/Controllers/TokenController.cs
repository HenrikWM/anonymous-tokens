using AnonymousTokensShared.Protocol;
using AnonymousTokensShared.Services.InMemory;

using Microsoft.AspNetCore.Mvc;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Utilities.Encoders;

using Server.TokenGeneration.Api.Models;

namespace Server.TokenGeneration.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly X9ECParameters _ecParameters;
        private TokenGenerator _tokenGenerator;

        public TokenController()
        {
            _ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);

            var publicKeyStore = new InMemoryPublicKeyStore();
            var publicKey = publicKeyStore.Get();

            var privateKeyStore = new InMemoryPrivateKeyStore();
            var privateKey = privateKeyStore.Get();

            _tokenGenerator = new TokenGenerator(publicKey, privateKey);
        }

        [Route("generate")]
        [HttpPost]
        public GenerateTokenResponseModel Generate(GenerateTokenRequestModel model)
        {
            var P = _ecParameters.Curve.DecodePoint(Hex.Decode(model.PAsHex));

            var token = _tokenGenerator.GenerateToken(_ecParameters, P);
            var Q = token.Q;
            var c = token.c;
            var z = token.z;

            return new GenerateTokenResponseModel(Q, c, z);
        }
    }
}
