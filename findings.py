class Findings:
    def __init__(
        self,
        name: str,
        status: str,
        severity: str,
        description: str,
        evidence: object,
    ) -> None:
        
        self.name = name
        self.status = status
        self.severity = severity
        self.description = description
        self.evidence = evidence

    def dictionary(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
        }