namespace N2.Core.Identity;

/// <summary>
/// Thrown when N2.Core.Identity is configured with a value it does not support, for example a
/// <see cref="Data.DatabaseProvider"/> other than <see cref="Data.DatabaseProvider.SqlServer"/>.
/// Raised at construction or context-creation time so a misconfiguration fails fast.
/// </summary>
public sealed class IdentityConfigurationException : Exception {
    public IdentityConfigurationException() {
    }

    public IdentityConfigurationException(string message) : base(message) {
    }

    public IdentityConfigurationException(string message, Exception innerException) : base(message, innerException) {
    }
}
