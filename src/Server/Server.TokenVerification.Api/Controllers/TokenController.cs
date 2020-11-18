using AnonymousTokensShared.Protocol;
using AnonymousTokensShared.Services.InMemory;

using Microsoft.AspNetCore.Mvc;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Utilities.Encoders;

using Server.TokenVerification.Api.Models;

namespace Server.TokenVerification.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly X9ECParameters _ecParameters;
        private TokenVerifier _tokenVerifier;

        public TokenController()
        {
            _ecParameters = CustomNamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);

            var privateKeyStore = new InMemoryPrivateKeyStore();
            var privateKey = privateKeyStore.Get();

            _tokenVerifier = new TokenVerifier(privateKey);
        }

        [Route("verify")]
        [HttpPost]
        public bool Verify(VerifyTokenRequestModel model)
        {
            var t = Hex.Decode(model.tAsHex);
            var W = _ecParameters.Curve.DecodePoint(Hex.Decode(model.WAsHex));

            var isValid = _tokenVerifier.VerifyToken(_ecParameters.Curve, t, W);

            return isValid;
        }
    }
}
