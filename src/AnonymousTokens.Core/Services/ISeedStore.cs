using System.Threading.Tasks;

namespace AnonymousTokens.Core.Services
{
    public interface ISeedStore
    {
        Task<bool> ExistsAsync(byte[] t);
        Task<bool> SaveAsync(byte[] t);
    }
}
