
using System.IO;
using System.Reflection;

namespace AnonymousTokens.Core.Services.InMemory
{
    public static class EmbeddedPemResource
    {
        public static object Load(string resource)
        {
            var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource);

            using StreamReader streamReader = new StreamReader(stream);

            return new Org.BouncyCastle.OpenSsl.PemReader(streamReader).ReadObject();
        }
    }
}
