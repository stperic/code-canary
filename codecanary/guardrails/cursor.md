# Cursor AI Security Rules
# Copy this file to .cursorrules in your project root

## Security Requirements

You MUST follow these security practices in all generated code:

### Secrets & Credentials
- NEVER hardcode API keys, passwords, tokens, or other secrets
- Use environment variables for all sensitive configuration
- Example: `os.environ.get("AWS_ACCESS_KEY_ID")` instead of string literals

### Cryptography
- Use SHA-256 or SHA-3 for hashing, NEVER MD5 or SHA-1
- Use PBKDF2, bcrypt, or Argon2 for password hashing
- Use AES-GCM or ChaCha20-Poly1305 for encryption, NEVER DES or RC4
- Use secrets.token_bytes() for random data, NEVER random.random()

### SQL & Database
- ALWAYS use parameterized queries or ORM methods
- NEVER concatenate user input into SQL strings
- Example: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`

### Input Validation
- Validate and sanitize ALL user input
- Use allowlists over denylists
- Escape output appropriately for the context (HTML, SQL, etc.)

### Network & HTTP
- Use HTTPS for all external requests
- Verify SSL/TLS certificates
- Validate redirect URLs to prevent open redirects

### Serialization
- NEVER use pickle, marshal, or yaml.load() with untrusted data
- Use json.loads() or yaml.safe_load() for untrusted data
- Validate deserialized data structure before use

### File Operations
- Validate file paths to prevent path traversal
- Use os.path.realpath() to resolve paths
- Check that resolved paths are within expected directories

## When Asked About Existing Code

When asked to modify or extend code that contains insecure patterns:
1. Point out the security issue
2. Suggest the secure alternative
3. Offer to refactor the insecure code

## Example Secure Patterns

```python
# ✅ Good: Environment variable for secrets
api_key = os.environ.get("API_KEY")

# ✅ Good: Parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# ✅ Good: Secure hash
import hashlib
hash_value = hashlib.sha256(data).hexdigest()

# ✅ Good: Secure random
import secrets
token = secrets.token_urlsafe(32)
```
