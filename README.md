# VillageSQL pgjwt Extension

Signs, verifies, and decodes JSON Web Tokens directly in SQL. Supports HMAC (HS256, HS384, HS512) and RSA (RS256) algorithms.

## Functions

### jwt_sign

```sql
vsql_pgjwt.jwt_sign(payload TEXT, secret TEXT, algorithm TEXT) -> TEXT
```

Signs a JSON payload and returns a compact JWS token.

```sql
SELECT vsql_pgjwt.jwt_sign('{"sub":"user-42","exp":1893456000}', 'shhh', 'HS256');
-- 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjoxODkzNDU2MDAwfQ.JWbmNYte_3w_mu1ru3O07Jt0BCt3Y0tKr4z4pEOIVXA'
```

For RS256, pass a PEM-encoded private key as the secret:

```sql
SELECT vsql_pgjwt.jwt_sign('{"sub":"user-42"}', @private_key, 'RS256');
```

### jwt_verify

```sql
vsql_pgjwt.jwt_verify(token TEXT, secret TEXT, algorithm TEXT) -> TEXT
```

Verifies a token's signature and checks `exp`/`nbf` claims against the current time. Returns a JSON envelope.

```sql
SELECT vsql_pgjwt.jwt_verify(
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjo5OTk5OTk5OTk5fQ.3mVWMgf8l4cGF47FqbQtb77353Uns4THWU5lGeoIKms',
    'shhh', 'HS256');
-- '{"valid":true,"header":{"alg":"HS256","typ":"JWT"},"payload":{"sub":"user-42","exp":9999999999}}'
```

For RS256 verification, pass the PEM-encoded public key:

```sql
SELECT vsql_pgjwt.jwt_verify(@token, @public_key, 'RS256');
```

### jwt_decode

```sql
vsql_pgjwt.jwt_decode(token TEXT) -> TEXT
```

Decodes a token's header and payload without verifying the signature.

```sql
SELECT vsql_pgjwt.jwt_decode(
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjoxODkzNDU2MDAwfQ.JWbmNYte_3w_mu1ru3O07Jt0BCt3Y0tKr4z4pEOIVXA');
-- '{"header":{"alg":"HS256","typ":"JWT"},"payload":{"sub":"user-42","exp":1893456000}}'
```

## Algorithms

| Algorithm | Type | Key |
|-----------|------|-----|
| HS256 | HMAC-SHA256 | Shared secret |
| HS384 | HMAC-SHA384 | Shared secret |
| HS512 | HMAC-SHA512 | Shared secret |
| RS256 | RSA PKCS#1 v1.5 + SHA-256 | PEM private key (sign) / PEM public key (verify) |

## Using with JSON functions

VEF STRING results currently use `binary` charset, so wrap the output with
`CONVERT(... USING utf8mb4)` before passing it to MySQL JSON functions:

```sql
SET @result = CONVERT(
  vsql_pgjwt.jwt_decode('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwiZXhwIjoxODkzNDU2MDAwfQ.JWbmNYte_3w_mu1ru3O07Jt0BCt3Y0tKr4z4pEOIVXA')
  USING utf8mb4
);
SELECT JSON_VALUE(@result, '$.payload.sub');
-- 'user-42'
```

## Error handling

`jwt_verify` and `jwt_decode` return `NULL` (with a warning) for invalid input
such as malformed tokens, bad base64, or unsupported algorithms. This allows
them to be used safely in queries over untrusted data:

```sql
SELECT id, vsql_pgjwt.jwt_verify(token, 'secret', 'HS256') FROM tokens;
-- rows with bad tokens get NULL instead of aborting the query
```

`jwt_sign` raises an error for unsupported algorithms or invalid keys, since
the caller controls those inputs.

## Installation

```sql
INSTALL EXTENSION vsql_pgjwt;
```

## Building from source

```bash
export VillageSQL_BUILD_DIR=/path/to/villagesql/build
./build.sh
```

## License

GPLv2 — see [LICENSE](LICENSE) for details.
