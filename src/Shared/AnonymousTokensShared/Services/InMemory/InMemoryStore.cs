
using System.IO;
using System.Reflection;

namespace AnonymousTokensShared.Services.InMemory
{
    public abstract class InMemoryStore
    {
        protected object LoadPemResource(string resource)
        {
            var stream = GetDataAsStream(resource);

            using StreamReader streamReader = new StreamReader(stream);

            return new Org.BouncyCastle.OpenSsl.PemReader(streamReader).ReadObject();
        }

        protected Stream GetDataAsStream(string name)
        {
            string fullName = GetFullName(name);

            return Assembly.GetExecutingAssembly().GetManifestResourceStream(fullName);
        }

        protected string GetFullName(string name)
        {
            return "AnonymousTokensShared.Services.InMemory." + name;
        }
    }
}
