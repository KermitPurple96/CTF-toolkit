# CTF-Toolkit E2E Testing Suite

Comprehensive end-to-end testing inspired by [project-forge](https://github.com/KermitPurple96/project-forge) testing methodology.

## Overview

This test suite provides thorough coverage of the CTF-toolkit functionality, ensuring reliability and security for CTF competitions and penetration testing workflows.

## Test Structure

```
tests/
├── __init__.py
├── test_e2e_flask_server.py    # Flask web server E2E tests
├── test_e2e_listener.py         # Shell listener functionality tests
└── README.md                    # This file
```

## Test Categories

### 1. Flask Server Tests (`test_e2e_flask_server.py`)

**Test Classes:**
- `TestHomePage` - Home page rendering
- `TestFileUpload` - File upload via PUT/POST
- `TestFileDownload` - File download functionality
- `TestToolsManagement` - Tool file management
- `TestClipboards` - Clipboard operations
- `TestIPDiscovery` - IP address discovery
- `TestShellsPage` - Shells interface
- `TestIntegration` - Multi-component integration tests

**Key Features Tested:**
- ✅ Path traversal prevention
- ✅ File upload/download integrity
- ✅ JSON API endpoints
- ✅ Tool file CRUD operations
- ✅ Clipboard state management
- ✅ Network interface discovery

### 2. Listener Tests (`test_e2e_listener.py`)

**Test Classes:**
- `TestANSICleaning` - ANSI escape sequence removal
- `TestMD5Calculation` - File integrity verification
- `TestFolderStructure` - Directory structure validation
- `TestFileTransferLogic` - File transfer helpers
- `TestIntegrationScenarios` - Complete workflow tests

**Key Features Tested:**
- ✅ ANSI code cleaning
- ✅ MD5 hash calculation
- ✅ File integrity verification
- ✅ Folder permissions
- ✅ File transfer corruption detection

## Running Tests

### Quick Start

```bash
# Run all tests
./run_tests.sh

# Run specific test suite
./run_tests.sh flask
./run_tests.sh listener

# Run with coverage report
./run_tests.sh all coverage
```

### Manual Test Execution

```bash
# Activate virtual environment
source .venv/bin/activate

# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_e2e_flask_server.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html --cov-report=term
```

### Test Selection

```bash
# Run only fast tests
pytest tests/ -v -m "not slow"

# Run security tests
pytest tests/ -v -m security

# Run specific test class
pytest tests/test_e2e_flask_server.py::TestFileUpload -v

# Run specific test function
pytest tests/test_e2e_flask_server.py::TestFileUpload::test_upload_prevents_path_traversal -v
```

## Test Markers

Tests are marked for easy categorization:

- `@pytest.mark.e2e` - End-to-end tests
- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.slow` - Slow-running tests
- `@pytest.mark.security` - Security-focused tests
- `@pytest.mark.network` - Tests requiring network access

## Security Testing

### Path Traversal Tests

The test suite includes comprehensive path traversal attack prevention tests:

```python
def test_upload_prevents_path_traversal(self, client):
    """Test that path traversal attacks are prevented"""
    # Try various attack vectors
    response = client.put('/upload/../../../etc/passwd', ...)
    assert response.status_code == 400
```

### File Integrity Tests

MD5 verification ensures file transfers maintain integrity:

```python
def test_file_integrity_workflow(self):
    """Test complete file integrity check workflow"""
    source_md5 = get_local_md5(source_path)
    dest_md5 = get_local_md5(dest_path)
    assert source_md5 == dest_md5
```

## Coverage Reports

After running tests with coverage:

```bash
./run_tests.sh all coverage
```

View the HTML report:
```bash
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install -r requirements-test.txt
      - name: Run tests
        run: pytest tests/ -v --cov=. --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Test Development Guidelines

### Writing New Tests

1. **Follow the AAA pattern**: Arrange, Act, Assert
   ```python
   def test_example(self, client):
       # Arrange
       test_data = b"test content"

       # Act
       response = client.put('/upload/test.txt', data=test_data)

       # Assert
       assert response.status_code == 200
   ```

2. **Use descriptive test names**: Test names should describe what they verify
   ```python
   def test_upload_file_via_put_creates_file_in_uploads_folder(self):
   ```

3. **Clean up after tests**: Always remove created files/resources
   ```python
   try:
       # Test code
   finally:
       if os.path.exists(test_file):
           os.unlink(test_file)
   ```

4. **Use fixtures for common setup**: Reduce code duplication
   ```python
   @pytest.fixture
   def temp_file():
       with tempfile.NamedTemporaryFile(delete=False) as f:
           yield f.name
       os.unlink(f.name)
   ```

### Test Isolation

Each test should be independent and not rely on other tests:
- ✅ Create necessary test data within the test
- ✅ Clean up all resources after the test
- ❌ Don't rely on execution order
- ❌ Don't share state between tests

## Debugging Failed Tests

### Verbose Output
```bash
pytest tests/test_e2e_flask_server.py -vv
```

### Show Print Statements
```bash
pytest tests/test_e2e_flask_server.py -s
```

### Run Single Test for Debugging
```bash
pytest tests/test_e2e_flask_server.py::TestFileUpload::test_upload_file_via_put -vv -s
```

### Use PDB Debugger
```bash
pytest tests/test_e2e_flask_server.py --pdb
```

## Performance Considerations

### Test Speed Optimization

- Mark slow tests with `@pytest.mark.slow`
- Use `pytest-xdist` for parallel execution:
  ```bash
  pip install pytest-xdist
  pytest tests/ -n auto
  ```

### Resource Management

- Use `tempfile` for temporary files
- Clean up in `finally` blocks
- Use fixtures with proper teardown

## Contributing

When adding new features to CTF-toolkit:

1. Write E2E tests first (TDD approach)
2. Ensure all tests pass: `./run_tests.sh`
3. Check coverage: `./run_tests.sh all coverage`
4. Run security scan: `./run_tests.sh security`
5. Document any new test markers or patterns

## Troubleshooting

### Common Issues

**Import errors:**
```bash
# Ensure virtual environment is activated
source .venv/bin/activate
pip install -r requirements-test.txt
```

**Port already in use:**
```bash
# Find and kill process using port 5000
lsof -ti:5000 | xargs kill -9
```

**Permission errors:**
```bash
# Ensure test folders have correct permissions
chmod 755 uploads downloads tools
```

## References

- [pytest Documentation](https://docs.pytest.org/)
- [Flask Testing](https://flask.palletsprojects.com/en/2.3.x/testing/)
- [Project Forge Testing Philosophy](https://github.com/KermitPurple96/project-forge)

---

**Test at the lowest tier that catches the bug** - Project Forge principle
