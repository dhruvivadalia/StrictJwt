using System.Text.Json;

namespace StrictJwt;

/// <summary>
/// Validates and normalizes JWT tokens against Base64url malleability attacks.
/// 
/// Base64url encodes 6 bits per character. When the binary length of a segment
/// is not an exact multiple of 3 bytes (such as HMAC-SHA256's 32 bytes, which
/// produces 43 Base64url characters), the final character contains 2 or 4 unused
/// "padding" bits. RFC 4648 / RFC 7515 specifies that these unused bits MUST be zero.
/// 
/// However, standard Base64 decoders ignore these residual bits, allowing attackers
/// to mutate them (e.g. changing 's' to 't', 'u', or 'v' in an HMAC-SHA256 signature)
/// while producing the exact same decoded bytes. This creates alternative valid tokens
/// that bypass string-based revocation lists, token blacklists, and cache keys.
/// 
/// Canonicalization collapses all equivalent encodings into a single unique form,
/// and strict validation rejects any token containing non-canonical bits.
/// </summary>
public static class JwtCanonicalizer
{
    private const string InvalidJwtStructure = "Invalid JWT structure: expected 3 segments separated by dots.";
    private const string InvalidBase64Url = "Segment '{0}' contains invalid Base64url characters or length.";
    private const string NonCanonicalToken = "Token contains non-canonical Base64url encoding. " +
        "This may indicate a Base64 malleability bypass attempt.";

    /// <summary>
    /// Converts a Base64url string to raw bytes, tolerating non-canonical padding bits
    /// so the token can be properly normalized.
    /// </summary>
    private static byte[] Base64UrlDecode(string base64Url)
    {
        var standard = base64Url.Replace('-', '+').Replace('_', '/');
        var padding = (4 - standard.Length % 4) % 4;
        if (padding > 0)
        {
            standard += new string('=', padding);
        }
        return Convert.FromBase64String(standard);
    }

    /// <summary>
    /// Converts bytes to standard canonical Base64url format (no padding, URL-safe characters,
    /// unused padding bits strictly zeroed according to RFC 7515 / RFC 4648).
    /// </summary>
    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    /// <summary>
    /// Validates that a string is valid Base64url: contains only [A-Za-z0-9_-]
    /// and does not have an illegal length (length % 4 == 1 is impossible in valid Base64).
    /// </summary>
    private static bool IsValidBase64Url(string s)
    {
        if (string.IsNullOrEmpty(s) || s.Length % 4 == 1)
        {
            return false;
        }

        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (!((c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||
                  c == '-' || c == '_'))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Normalizes a JWT to its canonical form by decoding and re-encoding
    /// each segment (header, payload, and signature). All Base64url malleable variants
    /// collapse to the exact same canonical string.
    /// 
    /// Example: Signatures ending in 's', 't', 'u', 'v' all normalize to 's'
    /// (the unique canonical encoding with padding bits zeroed).
    /// </summary>
    public static string Normalize(string jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            throw new ArgumentException(InvalidJwtStructure, nameof(jwt));

        var parts = jwt.Split('.');
        if (parts.Length != 3)
            throw new ArgumentException(InvalidJwtStructure, nameof(jwt));

        var normalized = new string[3];
        for (int index = 0; index < 3; index++)
        {
            var part = parts[index];

            if (string.IsNullOrEmpty(part))
                throw new ArgumentException(InvalidJwtStructure, nameof(jwt));

            if (!IsValidBase64Url(part))
            {
                var segmentName = index == 0 ? "header" : index == 1 ? "payload" : "signature";
                throw new ArgumentException(string.Format(InvalidBase64Url, segmentName), nameof(jwt));
            }

            try
            {
                var bytes = Base64UrlDecode(part);
                normalized[index] = Base64UrlEncode(bytes);
            }
            catch (FormatException ex)
            {
                var segmentName = index == 0 ? "header" : index == 1 ? "payload" : "signature";
                throw new ArgumentException(string.Format(InvalidBase64Url, segmentName), nameof(jwt), ex);
            }
        }

        return string.Join(".", normalized);
    }

    /// <summary>
    /// Checks whether a JWT is in canonical (standard RFC 7515) Base64url encoding.
    /// Returns false if any segment has non-canonical trailing padding bits (malleable encoding)
    /// or invalid characters.
    /// </summary>
    public static bool IsCanonical(string jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            return false;

        try
        {
            return Normalize(jwt) == jwt;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validates a JWT with strict Base64url encoding checks.
    /// Throws SecurityTokenException if non-canonical encoding is detected.
    /// </summary>
    public static void ValidateStrict(string jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            throw new ArgumentException(InvalidJwtStructure, nameof(jwt));

        if (!IsCanonical(jwt))
        {
            throw new Microsoft.IdentityModel.Tokens.SecurityTokenException(NonCanonicalToken);
        }
    }

    /// <summary>
    /// Validates that a token strictly matches an expected canonical token.
    /// Fails with SecurityTokenException if the token is malleable (t, u, v)
    /// or SecurityTokenInvalidSignatureException if the signature is altered (g).
    /// </summary>
    public static void ValidateAgainst(string jwt, string expectedCanonicalJwt)
    {
        ValidateStrict(jwt);

        if (!string.Equals(jwt, expectedCanonicalJwt, StringComparison.Ordinal))
        {
            throw new Microsoft.IdentityModel.Tokens.SecurityTokenInvalidSignatureException(
                "Token signature does not match the expected canonical token (altered signature or payload).");
        }
    }

    /// <summary>
    /// Extracts the jti (JWT ID) claim from a token, if present.
    /// For token revocation, always revoke by jti or by the canonical token string.
    /// </summary>
    public static string? GetJti(string jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt))
            throw new ArgumentException(InvalidJwtStructure, nameof(jwt));

        var parts = jwt.Split('.');
        if (parts.Length != 3)
            throw new ArgumentException(InvalidJwtStructure, nameof(jwt));

        try
        {
            var payloadBytes = Base64UrlDecode(parts[1]);
            using var doc = JsonDocument.Parse(payloadBytes);
            if (doc.RootElement.TryGetProperty("jti", out var jtiProp))
            {
                return jtiProp.GetString();
            }
            return null;
        }
        catch
        {
            return null;
        }
    }
}
