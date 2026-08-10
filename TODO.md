# CTF-Toolkit TODO List

## Security Improvements (From Code Review)

### High Priority 🔴

- [ ] **Add Authentication/Authorization**
  - Implement basic authentication (at minimum)
  - Add API key authentication
  - Implement session management
  - Consider OAuth2 for production deployments
  - Document that this is intended for trusted networks only

- [ ] **Fix Command Injection in listen_manager.py**
  - Add command validation in `send_command()`
  - Use whitelist of allowed commands
  - Add command length limits
  - Implement audit logging for all commands sent
  - Never trust data from compromised remote system

- [ ] **Add Input Validation to Shell Scripts**
  - Validate IP addresses with regex in `snmp_enum.sh`
  - Proper quoting: `"${variable}"` instead of `$variable`
  - Validate all user-supplied parameters in `privesc_linux.sh`
  - Add warnings for controlled CTF environments only
  - Sanitize file paths and directory names

### Medium Priority 🟡

- [ ] **Improve Content Security Policy**
  - Remove `unsafe-inline` and `unsafe-eval` from CSP
  - Use nonces for inline scripts
  - Move all JavaScript to external files
  - Requires refactoring HTML/JS code

- [ ] **Add Input Validation to save_tool Endpoint**
  - Add content size validation using `validate_content_size()`
  - Set maximum file sizes for different file types
  - Implement disk quota checks
  - Prevent DoS via disk exhaustion

- [ ] **Improve Error Handling**
  - Use specific exception types instead of generic Exception
  - Log actual exception with details for debugging
  - Return generic message to user (don't leak internals)
  - Add error codes for debugging
  - Implement structured error responses

- [ ] **Add Security Event Logging**
  - Add dedicated security event logger
  - Log all failed validation attempts
  - Implement log aggregation
  - Add alerts for suspicious patterns
  - Consider integrating with SIEM

- [ ] **Missing Command Validation in /send_command**
  - Add command logging with sanitization
  - Implement command length limits (already in validators.py but not used)
  - Consider adding a whitelist mode for production
  - Add audit logging for all commands sent

### Low Priority 🟢

- [ ] **Refactor Global Variables**
  - Encapsulate global state in `listen_manager.py` into a class
  - Remove global `conn` and `server` variables
  - Use proper state management

- [ ] **Add Complete Type Hints**
  - Add type hints consistently across entire codebase
  - Use mypy for type checking
  - Document complex types

- [ ] **Enable HSTS When Using HTTPS**
  - Uncomment HSTS header in `security_headers.py`
  - Enable only when `USE_HTTPS` is True in config
  - Set appropriate max-age

- [ ] **Use Better Password Examples**
  - Change "password123" to "YOUR_PASSWORD_HERE" in examples
  - Update `privesc_linux.sh` and documentation
  - Use obviously fake passwords

- [ ] **Eliminate Magic Numbers**
  - Extract magic numbers to named constants
  - Examples: timeout values, sleep durations, buffer sizes
  - Improve code readability

- [ ] **Standardize Error Messages**
  - Create consistent error message format
  - Use structured error responses
  - Add error codes

- [ ] **Add Docstrings to Shell Scripts**
  - Document complex logic in bash scripts
  - Add function headers
  - Explain CTF-specific techniques

## Features & Enhancements

### Testing 🧪

- [ ] **Add Unit Tests**
  - Unit tests for validators
  - Unit tests for rate limiter (including concurrency tests)
  - Unit tests for security headers
  - Update tests to use SHA256 instead of MD5

- [ ] **Add Integration Tests**
  - End-to-end tests for shell functionality
  - File upload/download with SHA256 verification
  - Rate limiting stress tests
  - Authentication bypass testing (once auth is added)

- [ ] **Add Security Tests**
  - Penetration testing of all endpoints
  - Fuzzing of input validation
  - Command injection testing
  - Path traversal testing
  - XSS testing on all user inputs
  - CSRF testing

### Documentation 📚

- [ ] **Create SECURITY.md**
  - Add security disclosure policy
  - Document security considerations
  - Add responsible disclosure guidelines
  - Contact information for security issues

- [ ] **Add security.txt**
  - Create `.well-known/security.txt`
  - Add disclosure policy
  - Add contact information

- [ ] **Update API Documentation**
  - Document all endpoints
  - Add authentication requirements
  - Include rate limit information
  - Add example requests/responses

- [ ] **Improve Installation Documentation**
  - Add HTTPS setup guide
  - Document environment variables
  - Add production deployment guide
  - Security hardening checklist

### Performance ⚡

- [ ] **Optimize Rate Limiter Cleanup**
  - Use more efficient data structure for cleanup
  - Consider background cleanup thread
  - Benchmark with many IPs

- [ ] **Fix Blocking Operations**
  - Use background tasks (Celery, RQ) for listener operations
  - Implement async handlers where appropriate
  - Don't block web requests waiting for connections

### New Features 🆕

- [ ] **Add HTTPS Support by Default**
  - Generate self-signed certificates automatically
  - Add Let's Encrypt integration option
  - Document HTTPS setup

- [ ] **Implement Request Signing**
  - Add request signing for API calls
  - Prevent replay attacks
  - Add timestamp validation

- [ ] **Add Intrusion Detection**
  - Detect suspicious patterns in requests
  - Alert on potential attacks
  - Automatic IP blocking for severe violations

- [ ] **Add Web Interface for Security Logs**
  - Real-time security event monitoring
  - Dashboard for rate limit status
  - Failed authentication attempts visualization

## Completed ✅

- [x] **Fix SECRET_KEY Regeneration** (2026-08-11)
  - Secret key now persists in `.secret_key` file
  - No longer regenerates on every restart
  - Secure permissions (0600)

- [x] **Replace MD5 with SHA256** (2026-08-11)
  - All file integrity checks use SHA256
  - Updated function names and documentation
  - Regex updated for 64-char hashes

- [x] **Add Thread-Safe Rate Limiter** (2026-08-11)
  - Added threading.Lock() for concurrency
  - All operations are now atomic
  - No race conditions

- [x] **Create Code Review Report** (2026-08-11)
  - Comprehensive security analysis
  - OWASP Top 10 evaluation
  - Identified critical and important issues

- [x] **Add Privilege Escalation Tools** (2026-08-11)
  - privesc_linux.sh with LinPEAS/pspy integration
  - privesc_windows.ps1 with WinPEAS integration
  - Comprehensive PRIVESC_GUIDE.md

- [x] **Add SNMP Enumeration Tools** (2026-08-11)
  - snmp_enum.sh automation script
  - SNMP_ENUMERATION_GUIDE.md documentation

## Notes

**Current Status:** Suitable for CTF competitions and controlled lab environments

**Production Use:** ⚠️ NOT suitable for public internet without:
- Authentication system
- Command injection fixes
- Input validation improvements
- Comprehensive security logging

**Reference:** See `CODE_REVIEW_REPORT.md` for detailed security analysis
