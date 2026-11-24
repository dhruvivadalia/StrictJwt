# StrictJwt

Strict JWT validation and Base64url malleability protection for ASP.NET Core and .NET.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## The Problem: Base64url Malleability in JWTs

In JSON Web Tokens (JWT), segments (Header, Payload, and Signature) are encoded using **Base64url** (RFC 7515 / RFC 4648).

Base64 encodes 6 bits per character. When a segment's byte length is not a multiple of 3 bytes (such as HMAC-SHA256's 32 bytes = 256 bits), the encoded string length is 43 characters (43 × 6 = 258 bits). The final character carries **2 unused residual padding bits**.

According to RFC 4648 §3.5:
> *The unused bits MUST be set to zero.*

When the 2 padding bits are `00`, the 43rd character is `'s'`. However, an attacker can mutate those 2 bits without changing the decoded 32-byte hash:
- `00` &rarr; `s` (canonical encoding)
- `01` &rarr; `t` (non-canonical malleable variant)
- `10` &rarr; `u` (non-canonical malleable variant)
- `11` &rarr; `v` (non-canonical malleable variant)

### Why Standard JWT Validators Accept All Four
Standard JWT libraries (such as `System.IdentityModel.Tokens.Jwt`, `Microsoft.IdentityModel.Tokens`, Node's `jsonwebtoken`, etc.) decode Base64url using standard Base64 decoders. Standard Base64 decoders shift out and discard the extra 2 bits.

As a result, tokens ending in `...OZs`, `...OZt`, `...OZu`, and `...OZv` **all decode to the identical 32 bytes**, and all pass signature verification!

### Security Vulnerabilities
1. **Revocation / Blacklist Bypass**:
   If an application invalidates tokens upon logout by storing token strings in Redis or a database (`revokedTokens.Contains(token)`), revoking `...OZs` does not stop an attacker from using `...OZt`, `...OZu`, or `...OZv`. The mutated token bypasses the blacklist check while still passing cryptographic signature verification!
2. **Cache Poisoning & Key Collision**:
   APIs that use raw token strings as cache keys or rate-limit keys can be tricked by token aliases.
3. **Audit Log & Session Fixation Confusion**:
   Four distinct token strings represent the exact same identity and session.

---

## Features

- **Strict Token Rejection**: Detects and rejects non-canonical tokens ending with malleable bits (like `t`, `u`, `v`).
- **Canonical Normalization**: Collapses all malleable variants (`...OZt`, `...OZu`, `...OZv`) to their unique canonical form (`...OZs`).
- **ASP.NET Core Authentication Integration**: Drop-in replacement with `AddStrictJwtBearer()`.
- **Early Pipeline Middleware**: Catch and reject malleable tokens before authentication handlers or controllers with `UseStrictJwt()`.
- **Zero-Allocation Bit Checking**: High-performance validation compatible with .NET 10+.

---

## Quick Start

### 1. ASP.NET Core `AddStrictJwtBearer`

Replace `AddJwtBearer` in your `Program.cs`:

```csharp
using StrictJwt.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddStrictJwtBearer(
        signingKey: builder.Configuration["Jwt:Key"]!,
        issuer: builder.Configuration["Jwt:Issuer"]!,
        audience: builder.Configuration["Jwt:Audience"]!,
        configureOptions: options =>
        {
            // Default: true (immediately rejects non-canonical tokens)
            options.ThrowOnNonCanonical = true;
        });

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
```

### 2. Early Pipeline Middleware

Reject non-canonical tokens at the edge:

```csharp
using StrictJwt.Middleware;

var app = builder.Build();

// Rejects non-canonical Bearer tokens with 401 Unauthorized
app.UseStrictJwt(rejectNonCanonical: true);

app.UseAuthentication();
app.UseAuthorization();
```

Or normalize incoming tokens in-flight for downstream systems:

```csharp
// Rewrites Authorization header to canonical form in-flight
app.UseStrictJwt(rejectNonCanonical: false, normalizeInFlight: true);
```

### 3. Safe Token Revocation & Blacklisting

Always store the canonical token string in your blacklist:

```csharp
using StrictJwt.Extensions;

// When logging out / revoking:
string rawToken = ...;
await redis.SetAddAsync("revoked_tokens", rawToken.ToCanonical());

// When checking revocation:
string incomingToken = ...;
if (await redis.SetContainsAsync("revoked_tokens", incomingToken.ToCanonical()))
{
    // Rejected! Catches all variants: s, t, u, v
}
```

### 4. Direct Validation

```csharp
using StrictJwt;

// Check if token has valid canonical encoding
bool isCanonical = JwtCanonicalizer.IsCanonical(token);

// Normalize any malleable token to its unique canonical representation
string canonicalToken = JwtCanonicalizer.Normalize(token);

// Throws SecurityTokenException if token contains non-canonical padding bits
JwtCanonicalizer.ValidateStrict(token);
```

---

## License

MIT License.
