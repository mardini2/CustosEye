# CustosEye Test Suite

## Overview
Comprehensive test suite for CustosEye with **275 tests** covering all major components.

## Test Statistics
- **Total Tests**: 275 (265 passing, 10 skipped)
- **Coverage**: All major modules
- **Status**: Complete - all planned tests implemented

## Test Files

### Agent Tests (70+ tests)
- `test_agent_monitor.py` - ProcessMonitor (15+ tests)
  - Hash caching and computation
  - Process event extraction
  - Windows signature extraction
  - Error handling (NoSuchProcess, AccessDenied, ZombieProcess)
  - Network connection extraction

- `test_agent_network_scan.py` - NetworkSnapshot (10+ tests)
  - Listening port extraction
  - Remote endpoint extraction
  - Connection filtering and deduplication
  - Error handling

- `test_agent_integrity_check.py` - IntegrityChecker (20+ tests)
  - File integrity monitoring
  - SHA256 hash computation
  - Path normalization (env vars, tilde, slashes)
  - State change detection
  - Missing file detection
  - Hash mismatch detection
  - Error handling

- `test_agent_rules_engine.py` - RulesEngine (15+ tests)
  - Rule loading from JSON
  - Rule matching (source, name, exe, ports, remote)
  - Rule evaluation
  - Condition combinations
  - First-match-wins logic

- `test_agent_win_sign.py` - Windows Signature (10+ tests)
  - Authenticode signature verification
  - PowerShell integration
  - Platform detection
  - Error handling
  - Path escaping

### Algorithm Tests (10+ tests)
- `test_csc_engine_core.py` - Trust engine core (existing, updated)
- `test_csc_engine_helpers.py` - Helper functions (existing, updated)

### Dashboard Tests (70+ tests)
- `test_dashboard_config.py` - Configuration (10+ tests)
  - Config loading from JSON
  - Environment variable overrides
  - Default values
  - Path resolution (normal and frozen)

- `test_dashboard_auth.py` - Authentication core (20+ tests)
  - User creation and validation
  - Password hashing (Argon2, bcrypt, SHA256 fallback)
  - Password verification
  - 2FA (TOTP, QR codes, backup codes)
  - Brute force protection
  - Password reset
  - Password change

- `test_dashboard_auth_routes.py` - Authentication routes (15+ tests)
  - CSRF token handling
  - Login/signup routes
  - 2FA routes
  - Password reset routes
  - Authentication decorators

- `test_dashboard_app.py` - Dashboard routes (25+ tests)
  - Main dashboard routes
  - API endpoints (events, proctree, integrity)
  - Export functionality (CSV, JSON, JSONL, XLSX)
  - Buffer management
  - Process index

### App Tests (10+ tests)
- `test_app_console.py` - Console entry point (10+ tests)
  - EventBus functionality
  - Component initialization
  - Banner printing
  - Command-line arguments

### Integration Tests (10+ tests)
- `test_integration.py` - End-to-end tests (10+ tests)
  - EventBus fan-out
  - Component interactions
  - Rules engine integration
  - CSC engine integration
  - Error handling across components

### Existing Tests (Updated)
- `test_events.py` - API event tests
- `test_integrity.py` - Integrity API tests
- `test_ping.py` - Ping endpoint tests
- `test_proctree.py` - Process tree API tests
- `test_about.py` - About endpoint tests
- `test_diff_formatting_fixes.py` - Diff formatting tests
- `test_diff_optional.py` - Optional diff tests
- `test_exe_smoke_optional.py` - EXE smoke tests

## Running Tests

### Run All Tests

**Basic command (verbose output):**
```bash
python -m pytest tests/ -v
```

**Recommended (verbose with short tracebacks):**
```bash
python -m pytest tests/ -v --tb=short
```

**Quiet mode (minimal output):**
```bash
python -m pytest tests/ -q
```

**Show test names only (collect without running):**
```bash
python -m pytest tests/ --collect-only
```

### Run Specific Tests

**Run specific test file:**
```bash
python -m pytest tests/test_agent_monitor.py -v
```

**Run specific test class:**
```bash
python -m pytest tests/test_agent_monitor.py::TestProcessMonitor -v
```

**Run specific test:**
```bash
python -m pytest tests/test_agent_monitor.py::TestProcessMonitor::test_monitor_initializes -v
```

**Run tests matching a pattern:**
```bash
python -m pytest tests/ -k "monitor" -v
```

### Test Execution Options

**Stop on first failure:**
```bash
python -m pytest tests/ -x
```

**Stop after N failures:**
```bash
python -m pytest tests/ --maxfail=3
```

**Show local variables on failure:**
```bash
python -m pytest tests/ -l
```

**Run in parallel (faster, requires pytest-xdist):**
```bash
pip install pytest-xdist
python -m pytest tests/ -n auto
```

**Run only failed tests from last run:**
```bash
python -m pytest tests/ --lf
```

**Run failed tests first, then rest:**
```bash
python -m pytest tests/ --ff
```

### Coverage Reports

**Run with coverage report:**
```bash
python -m pytest tests/ --cov=agent --cov=algorithm --cov=dashboard --cov=app
```

**Coverage with HTML report:**
```bash
python -m pytest tests/ --cov=agent --cov=algorithm --cov=dashboard --cov=app --cov-report=html
```
(Report will be in `htmlcov/index.html`)

**Coverage with terminal report:**
```bash
python -m pytest tests/ --cov=agent --cov=algorithm --cov=dashboard --cov=app --cov-report=term-missing
```

### Output Options

**Show print statements:**
```bash
python -m pytest tests/ -s
```

**Show print statements and verbose:**
```bash
python -m pytest tests/ -sv
```

**Show detailed traceback:**
```bash
python -m pytest tests/ --tb=long
```

**Show no traceback (just summary):**
```bash
python -m pytest tests/ --tb=no
```

### Useful Combinations

**Quick test run (quiet, stop on first failure):**
```bash
python -m pytest tests/ -qx
```

**Full diagnostic (verbose, show prints, long tracebacks):**
```bash
python -m pytest tests/ -sv --tb=long
```

**Development workflow (verbose, show prints, stop on failure):**
```bash
python -m pytest tests/ -svx
```

## Test Coverage

### Covered Components
a. Agent modules (monitor, network_scan, integrity_check, rules_engine, win_sign)
b. Algorithm (CSC trust engine)
c. Dashboard config
d. Dashboard auth core
e. Console entry point
f. Integration scenarios
g. Error handling
h. Edge cases

### Test Quality
- **Unit tests**: Test individual functions and classes
- **Integration tests**: Test component interactions
- **Error handling**: Test exception scenarios
- **Edge cases**: Test boundary conditions
- **Mocking**: Use mocks for external dependencies

## Test Organization

Tests are organized by module:
- `tests/test_agent_*.py` - Agent module tests
- `tests/test_algorithm_*.py` - Algorithm tests
- `tests/test_dashboard_*.py` - Dashboard tests
- `tests/test_app_*.py` - App tests
- `tests/test_integration.py` - Integration tests

## Notes

- All tests use pytest fixtures for setup/teardown
- Tests use temporary directories for file operations
- Mocking is used for external dependencies (psutil, subprocess, etc.)
- Tests are designed to be fast and isolated
- Windows-specific tests are skipped on non-Windows platforms

## Future Enhancements

Potential areas for additional tests:
- More integration scenarios
- Performance tests
- Load tests
- UI component tests (if frontend testing is added)