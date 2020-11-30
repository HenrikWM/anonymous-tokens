using System.Threading.Tasks;

namespace AnonymousTokens.Services
{
    public interface ISeedStore
    {
        Task<bool> ExistsAsync(byte[] t);
        Task<bool> SaveAsync(byte[] t);
    }
}
