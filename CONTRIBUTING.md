# Contributing to AIPET

Thank you for your interest in contributing to AIPET.
This project welcomes contributions from the global
security research community.

---

## Ways to Contribute

### 1. Report Bugs
Open a GitHub Issue with:
- AIPET version (python3 aipet.py --version)
- Operating system and Python version
- Steps to reproduce the bug
- Expected vs actual behaviour
- Error output if any

### 2. Add IoT Device Signatures
Extend the fingerprinting database in recon/fingerprint.py:
```python
"your_device_type": {
    "ports":    [port_numbers],
    "services": ["service_name"],
    "banners":  ["Banner", "Text", "Patterns"],
    "weight":   7
},
```

### 3. Add Firmware Patterns
Add credential, dangerous config, or vulnerable component
patterns to firmware/firmware_analyser.py.

### 4. Add Attack Modules
New protocol modules follow this structure:
- Create your_protocol/protocol_attacker.py
- Implement run_your_protocol_attacks(host, port)
- Return standardised results dictionary
- Add to aipet.py orchestrator

### 5. Improve the AI Model
- Add more IoT CVE data sources
- Improve feature engineering
- Test alternative model architectures
- Improve SHAP explanation generation

### 6. Documentation
- Fix typos or unclear explanations
- Add examples to README
- Add academic references

---

## Development Setup
```bash
git clone https://github.com/YOUR_USERNAME/AIPET.git
cd AIPET
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest
python3 -m pytest tests/ -v
```

All 30 tests must pass before submitting a pull request.

---

## Pull Request Process

1. Fork the repository
2. Create a feature branch:
   git checkout -b feature/your-feature-name
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass:
   python3 -m pytest tests/ -v
6. Update documentation if needed
7. Submit a pull request with a clear description

---

## Code Standards

- Follow PEP 8 Python style guidelines
- Add docstrings to all functions
- Add inline comments for non-obvious logic
- Keep functions focused and single-purpose
- Use descriptive variable names
- Handle exceptions gracefully

---

## Responsible Use Reminder

All contributions must comply with RESPONSIBLE_USE.md.
Do not contribute exploit payloads, malicious code,
or content that enables unauthorised access.
