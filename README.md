# multi-tenant-saloon-authz

- The JWK-Set Endpoint is available at `http://localhost:9000/oauth2/jwks` when the application is running.
- The OAuth2 Authorization Server Metadata Endpoint is available at `http://localhost:9000/.well-known/oauth-authorization-server` when the application is running.
- The OpenID Connect Provider Configuration Endpoint is available at `http://localhost:9000/.well-known/openid-configuration` when the application is running.

### client_credentials example

```shell
http -f POST :9000/oauth2/token grant_type=client_credentials scope='message.read' -a messaging-client:secret
```

- To introspect a token
```shell
TOKEN= http -f POST :9000/oauth2/token grant_type=client_credentials scope='message.read' -a messaging-client:secret | jq -r .access_token
http -f POST :9000/oauth2/introspect token=$TOKEN -a messaging-client:secret
```

---

For a public client (client-authentication-methods: none), Spring Authorization Server mandates PKCE. Here's the full flow:

### Step - 0 — Generate code_verifier and code_challenge

**Terminal (one-liner)**
```shell
# 1. Generate a random code_verifier
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | tr '+/' '-_' | head -c 43)

# 2. Generate code_challenge from it
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=' | tr '+/' '-_')

echo "verifier : $CODE_VERIFIER"
echo "challenge: $CODE_CHALLENGE"
```

**JavaScript (browser / Node)**
```js
const verifier = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

console.log(`challenge: ${challenge}`);
console.log(`verifier: ${verifier}`);
```

**Java**

```java
var verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(new SecureRandom().generateSeed(32));

var digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
var challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

IO.println("verifier : " + verifier);
IO.println("challenge: " + challenge);
```

Key rules for a valid code_verifier
- Length: 43–128 characters
- Characters: A-Z a-z 0-9 - . _ ~ only (RFC 7636)
- Must be cryptographically random, not reused

Key rules for code_challenge
- SHA-256(code_verifier) → raw bytes → Base64URL-encode → strip = padding
- Base64URL means: replace + → -, / → _, remove =


### Step 1 — Authorization Request (browser redirect)
```shell
GET http://localhost:9000/oauth2/authorize
    ?response_type=code
    &client_id=public-client
    &redirect_uri=http://127.0.0.1:3000
    &scope=openid profile
    &code_challenge=<BASE64URL(SHA256(code_verifier))>
    &code_challenge_method=S256
```
example
```shell
http://localhost:9000/oauth2/authorize?response_type=code&client_id=public-client&redirect_uri=http://127.0.0.1:3000&scope=openid%20profile&code_challenge=fj0Npk99PhWofo5EUIzwcR8nbm6DH05ChQwC4ev2IlE&code_challenge_method=S256
```
Your app generates a random code_verifier, hashes it to produce code_challenge, sends the hash here. The server redirects the user to the login page, and after authentication redirects back to:
```shell
http://127.0.0.1:3000?code=<AUTH_CODE>
```

### Step 2 — Token Exchange (back-channel POST, no secret needed)

```shell
http --form POST http://localhost:9000/oauth2/token \
  grant_type=authorization_code \
  code=<AUTH_CODE> \
  redirect_uri=http://127.0.0.1:3000 \
  client_id=public-client \
  code_verifier=<original_plain_code_verifier>
```

Server verifies SHA256(code_verifier) == code_challenge from Step 1. Returns:
```json
{
    "access_token": "...",
    "id_token": "...",
    "token_type": "Bearer",
    "expires_in": 1800
}
```
