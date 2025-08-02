# tests/test_finding_manual.py
from src.models.finding import Finding, Severity

def test_finding_creation():
    finding = Finding(
        file_path="app.py",
        line_number=42,
        rule_id="SQL_INJECTION",
        severity=Severity.HIGH,
        message="Possível SQL Injection detectado em query dinâmica"
    )
    
    print(finding)
    print(finding.to_json())

if __name__ == "__main__":
    test_finding_creation()