using AnonymousTokens.Server.Protocol;
using AnonymousTokens.Services;

using Microsoft.AspNetCore.Mvc;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Utilities.Encoders;

using Server.TokenGeneration.Api.Models;

using System.Threading.Tasks;

namespace Server.TokenGeneration.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly X9ECParameters _ecParameters;
        private readonly IPrivateKeyStore _privateKeyStore;
        private readonly IPublicKeyStore _publicKeyStore;
        private readonly ITokenGenerator _tokenGenerator;

        public TokenController(
            IPrivateKeyStore privateKeyStore,
            IPublicKeyStore publicKeyStore,
            ITokenGenerator tokenGenerator)
        {
            _privateKeyStore = privateKeyStore;
            _publicKeyStore = publicKeyStore;
            _tokenGenerator = tokenGenerator;
            _ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);
        }

        [Route("generate")]
        [HttpPost]
        public async Task<GenerateTokenResponseModel> GenerateAsync(GenerateTokenRequestModel model)
        {
            var k = await _privateKeyStore.GetAsync();
            var K = await _publicKeyStore.GetAsync();
            var P = _ecParameters.Curve.DecodePoint(Hex.Decode(model.PAsHex));

            var token = _tokenGenerator.GenerateToken(k, K.Q, _ecParameters, P);
            var Q = token.Q;
            var c = token.c;
            var z = token.z;

            return new GenerateTokenResponseModel(Q, c, z);
        }
    }
}
