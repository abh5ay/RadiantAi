class PolicyEngine:
    """Governance layer for RadiantAI medical decisions."""
    
    def __init__(self):
        # Professional clinical thresholds
        self.min_confidence = 65.0
        self.block_list = ["Placebo", "unverified_substance"]

    def validate_prescription(self, medicines):
        """Cross-checks doctor prescriptions against clinical safety rules."""
        violations = []
        is_valid = True
        
        for med in medicines:
            if med in self.block_list:
                violations.append(f"Substance '{med}' is prohibited by Clinical Governance.")
                is_valid = False
                
        return {
            "is_valid": is_valid,
            "violations": violations
        }
