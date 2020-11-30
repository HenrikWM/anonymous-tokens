
using AnonymousTokens.Server.Protocol;
using AnonymousTokens.Services;

using Microsoft.AspNetCore.Mvc;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Utilities.Encoders;

using Server.TokenVerification.Api.Models;

using System.Threading.Tasks;

namespace Server.TokenVerification.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly X9ECParameters _ecParameters;
        private readonly IPrivateKeyStore _privateKeyStore;
        private readonly ITokenVerifier _tokenVerifier;

        public TokenController(
            IPrivateKeyStore privateKeyStore,
            ITokenVerifier tokenVerifier)
        {
            _privateKeyStore = privateKeyStore;
            _tokenVerifier = tokenVerifier;
            _ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);
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
