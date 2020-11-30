using BenchmarkDotNet.Running;

namespace AnonymousTokens.Benchmarks
{
    public class Program
    {
        static void Main(string[] args) => BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
    }
}
