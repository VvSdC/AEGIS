"""
AEGIS Risk Scorer Engine
Calculates risk scores for AI systems using 40+ weighted signals.

Scoring Categories:
- Data Sensitivity (25%)
- Autonomy Level (20%)
- Impact Scope (20%)
- Model Risk (15%)
- Regulatory Exposure (10%)
- Organizational Readiness (10%)
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Literal
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskBreakdown:
    """Score breakdown by category."""
    data_sensitivity: float = 0.0
    autonomy_level: float = 0.0
    impact_scope: float = 0.0
    model_risk: float = 0.0
    regulatory_exposure: float = 0.0
    organizational_readiness: float = 0.0
    
    def to_dict(self) -> Dict[str, float]:
        return {
            "data_sensitivity": self.data_sensitivity,
            "autonomy_level": self.autonomy_level,
            "impact_scope": self.impact_scope,
            "model_risk": self.model_risk,
            "regulatory_exposure": self.regulatory_exposure,
            "organizational_readiness": self.organizational_readiness,
        }


@dataclass
class RiskScore:
    """Risk scoring result."""
    system_name: str
    score: float
    level: RiskLevel
    breakdown: RiskBreakdown
    recommendations: List[str]
    input_data: Dict[str, Any]
    assessed_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_name": self.system_name,
            "score": self.score,
            "level": self.level.value,
            "breakdown": self.breakdown.to_dict(),
            "recommendations": self.recommendations,
            "assessed_at": self.assessed_at.isoformat(),
        }


class RiskScorer:
    """
    AI System Risk Scorer.
    
    Uses 40+ weighted signals across 6 categories to produce
    a 0-100 risk score with level classification.
    """
    
    # Category weights (must sum to 1.0)
    WEIGHTS = {
        "data_sensitivity": 0.25,
        "autonomy_level": 0.20,
        "impact_scope": 0.20,
        "model_risk": 0.15,
        "regulatory_exposure": 0.10,
        "organizational_readiness": 0.10,
    }
    
    # Risk level thresholds
    THRESHOLDS = {
        RiskLevel.LOW: 25,
        RiskLevel.MEDIUM: 50,
        RiskLevel.HIGH: 75,
        RiskLevel.CRITICAL: 100,
    }
    
    # PII type risk scores
    PII_RISK_SCORES = {
        "ssn": 100,
        "health": 95,
        "financial": 90,
        "biometric": 95,
        "government_id": 85,
        "credentials": 100,
        "email": 40,
        "phone": 50,
        "name": 30,
        "address": 60,
        "dob": 55,
        "demographic": 50,
    }
    
    def __init__(self):
        """Initialize the risk scorer."""
        pass
    
    def _score_data_sensitivity(
        self,
        pii_involved: bool,
        pii_types: List[str],
        data_volume: str,
        cross_border_transfer: bool,
    ) -> tuple[float, List[str]]:
        """
        Score data sensitivity (25% weight).
        
        Signals:
        - PII presence and types
        - Data volume
        - Cross-border data transfers
        """
        score = 0.0
        recommendations = []
        
        # PII presence (base 40 points)
        if pii_involved:
            score += 40
            recommendations.append("Implement data minimization to reduce PII exposure")
            
            # Additional points for high-risk PII types
            max_pii_risk = 0
            for pii_type in pii_types:
                pii_risk = self.PII_RISK_SCORES.get(pii_type.lower(), 30)
                max_pii_risk = max(max_pii_risk, pii_risk)
            
            # Scale to 30 additional points
            score += (max_pii_risk / 100) * 30
            
            if any(t.lower() in ["ssn", "health", "financial", "biometric"] for t in pii_types):
                recommendations.append("High-risk PII detected — require enhanced encryption and access controls")
        
        # Data volume (20 points max)
        volume_scores = {"low": 5, "medium": 10, "high": 15, "very_high": 20}
        score += volume_scores.get(data_volume, 10)
        
        if data_volume in ["high", "very_high"]:
            recommendations.append(f"High data volume ({data_volume}) increases breach impact — implement tiered access")
        
        # Cross-border transfer (10 points)
        if cross_border_transfer:
            score += 10
            recommendations.append("Cross-border data transfer requires compliance with multiple jurisdictions")
        
        return min(score, 100), recommendations
    
    def _score_autonomy_level(
        self,
        autonomy_level: str,
        decision_type: str = None,
    ) -> tuple[float, List[str]]:
        """
        Score autonomy level (20% weight).
        
        Signals:
        - Level of automation
        - Type of decisions being made
        """
        score = 0.0
        recommendations = []
        
        # Autonomy level scoring
        autonomy_scores = {
            "advisory": 20,
            "human_in_loop": 40,
            "supervised_auto": 70,
            "fully_autonomous": 100,
        }
        score = autonomy_scores.get(autonomy_level, 50)
        
        if autonomy_level == "fully_autonomous":
            recommendations.append("Fully autonomous systems require robust monitoring and override capabilities")
            recommendations.append("Consider adding human-in-the-loop for high-stakes decisions")
        elif autonomy_level == "supervised_auto":
            recommendations.append("Ensure supervisory controls are effective and actively monitored")
        
        # Decision type modifiers
        if decision_type:
            high_risk_decisions = ["action", "classification", "recommendation"]
            if decision_type.lower() in high_risk_decisions and autonomy_level != "advisory":
                score = min(score + 10, 100)
        
        return score, recommendations
    
    def _score_impact_scope(
        self,
        affected_users: str,
        vulnerable_populations: bool,
        critical_infrastructure: bool,
    ) -> tuple[float, List[str]]:
        """
        Score impact scope (20% weight).
        
        Signals:
        - Number of affected users
        - Vulnerable populations
        - Critical infrastructure
        """
        score = 0.0
        recommendations = []
        
        # Affected users (50 points max)
        user_scores = {
            "internal_only": 10,
            "limited": 25,
            "broad": 40,
            "public": 50,
        }
        score = user_scores.get(affected_users, 25)
        
        if affected_users in ["broad", "public"]:
            recommendations.append(f"Large user base ({affected_users}) increases impact of errors — implement staged rollout")
        
        # Vulnerable populations (25 points)
        if vulnerable_populations:
            score += 25
            recommendations.append("Systems affecting vulnerable populations require enhanced fairness testing")
            recommendations.append("Consider additional oversight mechanisms for vulnerable user interactions")
        
        # Critical infrastructure (25 points)
        if critical_infrastructure:
            score += 25
            recommendations.append("Critical infrastructure designation requires compliance with sector-specific regulations")
            recommendations.append("Implement redundancy and failover mechanisms")
        
        return min(score, 100), recommendations
    
    def _score_model_risk(
        self,
        model_type: str = None,
        training_data_provenance: str = "unknown",
    ) -> tuple[float, List[str]]:
        """
        Score model risk (15% weight).
        
        Signals:
        - Model type and capabilities
        - Training data provenance
        - Known limitations
        """
        score = 0.0
        recommendations = []
        
        # Training data provenance (60 points max)
        provenance_scores = {
            "unknown": 60,
            "partial": 40,
            "documented": 20,
            "verified": 10,
        }
        score = provenance_scores.get(training_data_provenance, 50)
        
        if training_data_provenance in ["unknown", "partial"]:
            recommendations.append("Improve training data documentation to reduce model risk uncertainty")
        
        # Model type risk modifiers
        if model_type:
            high_risk_types = ["generation", "decision", "classification"]
            if model_type.lower() in high_risk_types:
                score += 20
                recommendations.append(f"Generative/decision models ({model_type}) require output validation")
        
        # Baseline hallucination risk for LLMs
        score += 20  # LLMs inherently have hallucination risk
        recommendations.append("Implement output verification for factual claims")
        
        return min(score, 100), recommendations
    
    def _score_regulatory_exposure(
        self,
        applicable_regulations: List[str],
        high_risk_classification: bool,
    ) -> tuple[float, List[str]]:
        """
        Score regulatory exposure (10% weight).
        
        Signals:
        - Number of applicable regulations
        - High-risk classification status
        """
        score = 0.0
        recommendations = []
        
        # Number of regulations (scaled to 60 points)
        reg_count = len(applicable_regulations)
        score = min(reg_count * 15, 60)
        
        if reg_count > 0:
            recommendations.append(f"Ensure compliance with: {', '.join(applicable_regulations)}")
        
        # High-risk classification (40 points)
        if high_risk_classification:
            score += 40
            recommendations.append("High-risk classification requires enhanced documentation and oversight")
            recommendations.append("Conformity assessment may be required before deployment")
        
        return min(score, 100), recommendations
    
    def _score_organizational_readiness(
        self,
        existing_controls: str,
        team_training: bool,
        incident_response_plan: bool,
    ) -> tuple[float, List[str]]:
        """
        Score organizational readiness (10% weight).
        
        NOTE: Higher readiness = LOWER risk score.
        
        Signals:
        - Existing controls
        - Team training status
        - Incident response planning
        """
        score = 100.0  # Start at max risk
        recommendations = []
        
        # Existing controls reduce risk (up to 50 points)
        control_reductions = {
            "none": 0,
            "basic": 15,
            "moderate": 30,
            "comprehensive": 50,
        }
        score -= control_reductions.get(existing_controls, 0)
        
        if existing_controls in ["none", "basic"]:
            recommendations.append("Strengthen existing controls to reduce operational risk")
        
        # Team training reduces risk (20 points)
        if team_training:
            score -= 20
        else:
            recommendations.append("Implement AI-specific training for teams working with this system")
        
        # Incident response plan reduces risk (30 points)
        if incident_response_plan:
            score -= 30
        else:
            recommendations.append("Develop an incident response plan for AI-related issues")
        
        return max(score, 0), recommendations
    
    def _classify_level(self, score: float) -> RiskLevel:
        """Classify score into risk level."""
        if score < self.THRESHOLDS[RiskLevel.LOW]:
            return RiskLevel.LOW
        elif score < self.THRESHOLDS[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif score < self.THRESHOLDS[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def score(
        self,
        system_name: str,
        # Data Sensitivity signals
        pii_involved: bool = False,
        pii_types: List[str] = None,
        data_volume: str = "medium",
        cross_border_transfer: bool = False,
        # Autonomy Level signals
        autonomy_level: str = "advisory",
        decision_type: str = None,
        # Impact Scope signals
        affected_users: str = "limited",
        vulnerable_populations: bool = False,
        critical_infrastructure: bool = False,
        # Model Risk signals
        model_type: str = None,
        training_data_provenance: str = "unknown",
        # Regulatory Exposure signals
        applicable_regulations: List[str] = None,
        high_risk_classification: bool = False,
        # Organizational Readiness signals
        existing_controls: str = "basic",
        team_training: bool = False,
        incident_response_plan: bool = False,
    ) -> RiskScore:
        """
        Calculate risk score for an AI system.
        
        Returns a RiskScore with 0-100 score, level classification,
        category breakdown, and recommendations.
        """
        pii_types = pii_types or []
        applicable_regulations = applicable_regulations or []
        
        all_recommendations = []
        breakdown = RiskBreakdown()
        
        # Score each category
        breakdown.data_sensitivity, recs = self._score_data_sensitivity(
            pii_involved, pii_types, data_volume, cross_border_transfer
        )
        all_recommendations.extend(recs)
        
        breakdown.autonomy_level, recs = self._score_autonomy_level(
            autonomy_level, decision_type
        )
        all_recommendations.extend(recs)
        
        breakdown.impact_scope, recs = self._score_impact_scope(
            affected_users, vulnerable_populations, critical_infrastructure
        )
        all_recommendations.extend(recs)
        
        breakdown.model_risk, recs = self._score_model_risk(
            model_type, training_data_provenance
        )
        all_recommendations.extend(recs)
        
        breakdown.regulatory_exposure, recs = self._score_regulatory_exposure(
            applicable_regulations, high_risk_classification
        )
        all_recommendations.extend(recs)
        
        breakdown.organizational_readiness, recs = self._score_organizational_readiness(
            existing_controls, team_training, incident_response_plan
        )
        all_recommendations.extend(recs)
        
        # Calculate weighted total score
        total_score = (
            breakdown.data_sensitivity * self.WEIGHTS["data_sensitivity"] +
            breakdown.autonomy_level * self.WEIGHTS["autonomy_level"] +
            breakdown.impact_scope * self.WEIGHTS["impact_scope"] +
            breakdown.model_risk * self.WEIGHTS["model_risk"] +
            breakdown.regulatory_exposure * self.WEIGHTS["regulatory_exposure"] +
            breakdown.organizational_readiness * self.WEIGHTS["organizational_readiness"]
        )
        
        # Classify level
        level = self._classify_level(total_score)
        
        # Store input data for audit
        input_data = {
            "pii_involved": pii_involved,
            "pii_types": pii_types,
            "data_volume": data_volume,
            "cross_border_transfer": cross_border_transfer,
            "autonomy_level": autonomy_level,
            "decision_type": decision_type,
            "affected_users": affected_users,
            "vulnerable_populations": vulnerable_populations,
            "critical_infrastructure": critical_infrastructure,
            "model_type": model_type,
            "training_data_provenance": training_data_provenance,
            "applicable_regulations": applicable_regulations,
            "high_risk_classification": high_risk_classification,
            "existing_controls": existing_controls,
            "team_training": team_training,
            "incident_response_plan": incident_response_plan,
        }
        
        return RiskScore(
            system_name=system_name,
            score=round(total_score, 2),
            level=level,
            breakdown=breakdown,
            recommendations=list(set(all_recommendations)),  # Deduplicate
            input_data=input_data,
        )


# Singleton instance
_risk_scorer: RiskScorer = None


def get_risk_scorer() -> RiskScorer:
    """Get or create the risk scorer singleton."""
    global _risk_scorer
    if _risk_scorer is None:
        _risk_scorer = RiskScorer()
    return _risk_scorer
