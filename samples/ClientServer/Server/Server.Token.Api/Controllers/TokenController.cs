using AnonymousTokens.Core.Services;
using AnonymousTokens.Server.Protocol;

using Microsoft.AspNetCore.Mvc;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Utilities.Encoders;

using Server.Token.Api.Models;

using System.Threading.Tasks;

namespace Server.Token.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly IPrivateKeyStore _privateKeyStore;
        private readonly IPublicKeyStore _publicKeyStore;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly ITokenVerifier _tokenVerifier;

        private readonly X9ECParameters _ecParameters;

        public TokenController(
            IPrivateKeyStore privateKeyStore,
            IPublicKeyStore publicKeyStore,
            ITokenGenerator tokenGenerator,
            ITokenVerifier tokenVerifier)
        {
            _privateKeyStore = privateKeyStore;
            _publicKeyStore = publicKeyStore;
            _tokenGenerator = tokenGenerator;
            _tokenVerifier = tokenVerifier;

            _ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);
        }

        [Route("generate")]
        [HttpPost]
        public async Task<GenerateTokenResponseModel> Generate(GenerateTokenRequestModel model)
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

        [Route("verify")]
        [HttpPost]
        public async Task<bool> Verify(VerifyTokenRequestModel model)
        {
            var k = await _privateKeyStore.GetAsync();
            var t = Hex.Decode(model.tAsHex);
            var W = _ecParameters.Curve.DecodePoint(Hex.Decode(model.WAsHex));

            var isValid = await _tokenVerifier.VerifyTokenAsync(k, _ecParameters.Curve, t, W);

            return isValid;
        }
    }
}
