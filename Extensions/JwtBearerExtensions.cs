using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace StrictJwt.Extensions;

/// <summary>
/// Provides extension methods for strict JWT Bearer authentication
/// with Base64url malleability protection.
/// </summary>
public static class JwtBearerExtensions
{
    /// <summary>
    /// Configures JWT Bearer authentication with strict Base64url validation.
    /// Non-canonical tokens are rejected before reaching your controllers.
    /// </summary>
    public static AuthenticationBuilder AddStrictJwtBearer(
        this AuthenticationBuilder builder,
        string signingKey,
        string issuer,
        string audience,
        Action<StrictJwtOptions>? configureOptions = null)
    {
        return builder.AddStrictJwtBearer(
            JwtBearerDefaults.AuthenticationScheme,
            options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = issuer,
                    ValidateAudience = true,
                    ValidAudience = audience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    NameClaimType = ClaimTypes.NameIdentifier,
                    RoleClaimType = ClaimTypes.Role,
                };
            },
            configureOptions);
    }

    /// <summary>
    /// Configures JWT Bearer authentication with strict Base64url validation
    /// using custom JwtBearerOptions.
    /// </summary>
    public static AuthenticationBuilder AddStrictJwtBearer(
        this AuthenticationBuilder builder,
        Action<JwtBearerOptions> configureJwtBearer,
        Action<StrictJwtOptions>? configureOptions = null)
    {
        return builder.AddStrictJwtBearer(
            JwtBearerDefaults.AuthenticationScheme,
            configureJwtBearer,
            configureOptions);
    }

    /// <summary>
    /// Configures JWT Bearer authentication with strict Base64url validation
    /// under a specific authentication scheme.
    /// </summary>
    public static AuthenticationBuilder AddStrictJwtBearer(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<JwtBearerOptions> configureJwtBearer,
        Action<StrictJwtOptions>? configureOptions = null)
    {
        var strictOptions = new StrictJwtOptions();
        configureOptions?.Invoke(strictOptions);

        return builder.AddJwtBearer(authenticationScheme, options =>
        {
            configureJwtBearer(options);

            var originalEvents = options.Events;

            options.Events = new JwtBearerEvents
            {
                OnMessageReceived = async context =>
                {
                    if (originalEvents?.OnMessageReceived != null)
                    {
                        await originalEvents.OnMessageReceived(context);
                    }

                    // Extract token from context.Token or Authorization header
                    var rawToken = context.Token;
                    if (string.IsNullOrEmpty(rawToken))
                    {
                        var authHeader = context.Request.Headers.Authorization.ToString();
                        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                        {
                            rawToken = authHeader.Substring(7).Trim();
                        }
                    }

                    if (!string.IsNullOrEmpty(rawToken) && !JwtCanonicalizer.IsCanonical(rawToken))
                    {
                        if (strictOptions.ThrowOnNonCanonical)
                        {
                            context.Fail(new SecurityTokenException(
                                "Token contains non-canonical Base64url encoding (potential malleability bypass attempt)."));
                        }
                    }
                },
                OnTokenValidated = async context =>
                {
                    if (originalEvents?.OnTokenValidated != null)
                    {
                        await originalEvents.OnTokenValidated(context);
                    }

                    var rawToken = (context.SecurityToken as JwtSecurityToken)?.RawData;
                    if (string.IsNullOrEmpty(rawToken))
                    {
                        var authHeader = context.Request.Headers.Authorization.ToString();
                        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                        {
                            rawToken = authHeader.Substring(7).Trim();
                        }
                    }

                    if (!string.IsNullOrEmpty(rawToken) && !JwtCanonicalizer.IsCanonical(rawToken))
                    {
                        if (strictOptions.ThrowOnNonCanonical)
                        {
                            context.Fail(new SecurityTokenException(
                                "Token contains non-canonical Base64url encoding (potential malleability bypass attempt)."));
                        }
                    }
                },
                OnAuthenticationFailed = async context =>
                {
                    if (originalEvents?.OnAuthenticationFailed != null)
                    {
                        await originalEvents.OnAuthenticationFailed(context);
                    }
                },
                OnChallenge = async context =>
                {
                    if (originalEvents?.OnChallenge != null)
                    {
                        await originalEvents.OnChallenge(context);
                    }
                },
                OnForbidden = async context =>
                {
                    if (originalEvents?.OnForbidden != null)
                    {
                        await originalEvents.OnForbidden(context);
                    }
                }
            };
        });
    }

    /// <summary>
    /// Validates a JWT token string with strict Base64url checks,
    /// then returns the decoded claims principal if valid.
    /// </summary>
    public static ClaimsPrincipal ValidateStrict(
        this JwtSecurityTokenHandler handler,
        string token,
        TokenValidationParameters validationParams,
        StrictJwtOptions? strictOptions = null)
    {
        return handler.ValidateStrict(token, validationParams, strictOptions, out _);
    }

    /// <summary>
    /// Validates a JWT token string with strict Base64url checks,
    /// returning the decoded claims principal and validated token.
    /// </summary>
    public static ClaimsPrincipal ValidateStrict(
        this JwtSecurityTokenHandler handler,
        string token,
        TokenValidationParameters validationParams,
        StrictJwtOptions? strictOptions,
        out SecurityToken validatedToken)
    {
        strictOptions ??= new StrictJwtOptions();

        if (strictOptions.ThrowOnNonCanonical)
        {
            JwtCanonicalizer.ValidateStrict(token);
        }
        else if (!JwtCanonicalizer.IsCanonical(token))
        {
            Console.WriteLine($"[StrictJwt] Non-canonical token detected (audit mode): {token}");
        }

        return handler.ValidateToken(token, validationParams, out validatedToken);
    }

    /// <summary>
    /// Generates a canonical representation of a token for storage, comparison, or blacklisting.
    /// Always use this when storing tokens in databases, caches, or revocation lists.
    /// </summary>
    public static string ToCanonical(this string jwt)
    {
        return JwtCanonicalizer.Normalize(jwt);
    }
}

/// <summary>
/// Configuration options for strict JWT validation.
/// </summary>
public class StrictJwtOptions
{
    private bool _throwOnNonCanonical = true;

    /// <summary>
    /// If true, non-canonical tokens are rejected immediately.
    /// If false, they are logged or audited but allowed through.
    /// Default: true (reject).
    /// </summary>
    public bool ThrowOnNonCanonical
    {
        get => _throwOnNonCanonical;
        set => _throwOnNonCanonical = value;
    }

    /// <summary>
    /// If true, non-canonical tokens are allowed through (audit/warning mode).
    /// If false, they are rejected immediately.
    /// Default: false.
    /// </summary>
    public bool AllowNonCanonical
    {
        get => !_throwOnNonCanonical;
        set => _throwOnNonCanonical = !value;
    }
}
