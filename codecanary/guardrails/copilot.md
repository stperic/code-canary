# GitHub Copilot Security Instructions
# Copy this file to .github/copilot-instructions.md in your project

## Security Guidelines for Code Generation

GitHub Copilot should follow these security practices when generating code for this project.

### Authentication & Secrets

- Never suggest hardcoded credentials, API keys, or passwords
- Always use environment variables or secure secret management
- Suggest secure password hashing (bcrypt, Argon2) for authentication
- Recommend proper session management practices

### Database Security

- Always generate parameterized queries to prevent SQL injection
- Suggest using ORM methods over raw SQL when available
- Include proper input validation before database operations
- Recommend prepared statements for all user-supplied data

### Cryptography

- Use modern cryptographic algorithms (AES-256-GCM, SHA-256+)
- Never suggest deprecated algorithms (MD5, SHA-1, DES, RC4)
- Use cryptographically secure random number generators
- Recommend established cryptographic libraries over custom implementations

### Input/Output Handling

- Include input validation for all user-supplied data
- Suggest proper output encoding based on context (HTML, URL, SQL)
- Recommend allowlist validation over denylist
- Handle file uploads securely with type and size validation

### Network Security

- Always use HTTPS for external communications
- Verify SSL/TLS certificates
- Validate and sanitize URLs before making requests
- Implement proper CORS policies for web applications

### Serialization

- Never suggest pickle or marshal for untrusted data
- Use safe deserialization methods (yaml.safe_load, json.loads)
- Validate deserialized data structure and types

### Error Handling

- Avoid exposing sensitive information in error messages
- Log errors securely without sensitive data
- Implement proper exception handling

## Code Review Mindset

When suggesting code:
1. Consider security implications first
2. Follow the principle of least privilege
3. Prefer secure defaults over configuration options
4. Include security-related comments where appropriate

## Example Patterns to Follow

```python
# Secure secret handling
import os
api_key = os.environ["API_KEY"]  # Fail if not set

# Secure database query
cursor.execute(
    "SELECT * FROM users WHERE email = %s",
    (email,)  # Parameterized
)

# Secure hashing
import hashlib
digest = hashlib.sha256(data.encode()).hexdigest()

# Secure random
import secrets
token = secrets.token_urlsafe(32)
```
