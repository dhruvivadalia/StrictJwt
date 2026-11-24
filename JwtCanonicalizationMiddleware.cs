using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace StrictJwt.Middleware;

/// <summary>
/// Middleware that inspects incoming Bearer tokens for non-canonical Base64url encoding.
/// Protects against Base64 malleability attacks before requests reach authentication handlers
/// or controllers.
/// </summary>
public class JwtCanonicalizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly bool _rejectNonCanonical;
    private readonly bool _normalizeInFlight;

    /// <summary>
    /// Initializes a new instance of the <see cref="JwtCanonicalizationMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="rejectNonCanonical">Whether to reject non-canonical tokens immediately with 401.</param>
    /// <param name="normalizeInFlight">Whether to rewrite the Authorization header to canonical form in-flight.</param>
    public JwtCanonicalizationMiddleware(
        RequestDelegate next,
        bool rejectNonCanonical = true,
        bool normalizeInFlight = false)
    {
        _next = next;
        _rejectNonCanonical = rejectNonCanonical;
        _normalizeInFlight = normalizeInFlight;
    }

    /// <summary>
    /// Processes an incoming HTTP request and checks the Authorization header for non-canonical tokens.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    public async Task InvokeAsync(HttpContext context)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();

        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = authHeader.Substring(7).Trim();

            if (!string.IsNullOrEmpty(token) && !JwtCanonicalizer.IsCanonical(token))
            {
                // Log the non-canonical attempt
                Console.WriteLine(
                    $"[StrictJwt] Non-canonical JWT detected from {context.Connection.RemoteIpAddress}");

                if (_rejectNonCanonical)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "text/plain";
                    await context.Response.WriteAsync("Unauthorized: Non-canonical token encoding detected.");
                    return;
                }
                else if (_normalizeInFlight)
                {
                    // Rewrite Authorization header to its canonical form
                    var canonicalToken = JwtCanonicalizer.Normalize(token);
                    context.Request.Headers.Authorization = $"Bearer {canonicalToken}";
                }
            }
        }

        await _next(context);
    }
}

/// <summary>
/// Extension methods for registering JwtCanonicalizationMiddleware.
/// </summary>
public static class JwtCanonicalizationMiddlewareExtensions
{
    /// <summary>
    /// Adds strict JWT canonicalization middleware to the pipeline.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="rejectNonCanonical">Whether to reject non-canonical tokens with 401 Unauthorized (default: true).</param>
    /// <param name="normalizeInFlight">If rejectNonCanonical is false, whether to rewrite the Authorization header with the canonical token (default: false).</param>
    public static IApplicationBuilder UseStrictJwt(
        this IApplicationBuilder app,
        bool rejectNonCanonical = true,
        bool normalizeInFlight = false)
    {
        return app.UseMiddleware<JwtCanonicalizationMiddleware>(rejectNonCanonical, normalizeInFlight);
    }
}
