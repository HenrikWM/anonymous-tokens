namespace AnonymousTokens.Shared.Services
{
    public interface ISeedStore
    {
        bool Exists(byte[] t);
        bool Save(byte[] t);
    }
}
