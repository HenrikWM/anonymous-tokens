using System;

namespace AnonymousTokens
{
    public class AnonymousTokensException
        : Exception
    {
        public AnonymousTokensException()
            : base()
        {
        }

        public AnonymousTokensException(
            string message)
            : base(message)
        {
        }

        public AnonymousTokensException(
            string message,
            Exception exception)
            : base(message, exception)
        {
        }
    }
}
