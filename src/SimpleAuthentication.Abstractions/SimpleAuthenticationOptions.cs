namespace SimpleAuthentication;

/// <summary>
/// Options for SimpleAuthentication initialization
/// </summary>
public class SimpleAuthenticationOptions
{
    /// <summary>
    /// The method that create refresh token, and optionally store it
    /// </summary>
    public Func<string, Task<string>>? CreateAndGetRefreshTokenMethod { get; set; }

    /// <summary>
    /// The method that check the refresh token for a user.
    /// The first parameter must be the refresh token
    /// The second parameter must be the username
    /// </summary>    
    public Func<string, string, Task<bool>>? VerifyRefreshTokenMethod { get; set; }
}
