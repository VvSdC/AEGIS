"""
Region-based regulatory policy definitions.

Maps each supported region to its applicable acts, regulations, and frameworks.
Used to construct a compliance instruction header prepended to prompts before
sending to the model.
"""

from typing import Dict, List


REGION_POLICIES: Dict[str, Dict[str, any]] = {
    "india": {
        "acts": [
            "Digital Personal Data Protection Act (DPDPA) 2023",
            "Information Technology Act 2000",
            "NITI Aayog Responsible AI Principles",
            "RBI Data Localization Norms",
        ],
        "summary": (
            "You must not process, store, or reveal any personal data without explicit consent. "
            "Do not facilitate cross-border data transfer that violates data localization requirements. "
            "Ensure fairness, transparency, and accountability in all responses."
        ),
    },
    "china": {
        "acts": [
            "Personal Information Protection Law (PIPL)",
            "Cybersecurity Law of the People's Republic of China",
            "Data Security Law",
            "Generative AI Management Measures 2023",
            "Deep Synthesis Regulations",
        ],
        "summary": (
            "You must not generate content that undermines state security, public interest, or social stability. "
            "Do not produce deepfakes or synthetic content without disclosure. "
            "Do not process personal information beyond the minimum scope necessary. "
            "Ensure generated content is truthful and accurate."
        ),
    },
    "europe": {
        "acts": [
            "EU AI Act 2024",
            "General Data Protection Regulation (GDPR)",
            "Digital Services Act (DSA)",
            "ePrivacy Directive",
        ],
        "summary": (
            "You must respect the right to explanation for automated decisions. "
            "Do not process personal data without lawful basis. "
            "Apply data minimization principles. "
            "Disclose that you are an AI system when relevant. "
            "Do not engage in prohibited AI practices including social scoring, "
            "real-time biometric identification, or manipulation of vulnerable groups."
        ),
    },
    "usa": {
        "acts": [
            "NIST AI Risk Management Framework (AI RMF)",
            "Executive Order on Safe, Secure, and Trustworthy AI 2023",
            "California Consumer Privacy Act (CCPA/CPRA)",
            "FTC Guidelines on AI and Automated Decision-Making",
        ],
        "summary": (
            "You must be transparent about AI-generated content. "
            "Do not engage in unfair or deceptive practices. "
            "Respect consumer rights to data access, deletion, and opt-out. "
            "Apply risk management principles: identify, assess, and mitigate potential harms."
        ),
    },
    "australia": {
        "acts": [
            "Privacy Act 1988",
            "AI Ethics Framework (Department of Industry, Science and Resources)",
            "Online Safety Act 2021",
            "Consumer Data Right (CDR)",
            "Voluntary AI Safety Standard",
        ],
        "summary": (
            "You must protect personal information in accordance with the Australian Privacy Principles. "
            "Do not generate content that is harmful, offensive, or that facilitates online abuse. "
            "Ensure AI outputs are fair, contestable, and accountable. "
            "Respect consumer data rights and do not misuse shared data."
        ),
    },
}


def build_compliance_header(region: str) -> str:
    """
    Build a system-level compliance instruction header for the given region.
    This is prepended to the user's prompt before sending to the model.
    """
    policy = REGION_POLICIES.get(region)
    if not policy:
        policy = REGION_POLICIES["india"]

    acts_list = "\n".join(f"  - {act}" for act in policy["acts"])

    header = (
        f"[COMPLIANCE DIRECTIVE — Region: {region.upper()}]\n"
        f"You are operating under the following regulatory framework. "
        f"You MUST comply with all applicable regulations listed below:\n\n"
        f"{acts_list}\n\n"
        f"Compliance requirements:\n"
        f"{policy['summary']}\n\n"
        f"REFUSAL FORMAT (MANDATORY): If answering the user's request would violate ANY of the above regulations, "
        f"you MUST refuse using EXACTLY this format:\n\n"
        f"I cannot fulfill this request.\n\n"
        f"Violated Regulations:\n"
        f"- [EXACT ACT NAME from the list above]: [Brief reason why it is violated]\n"
        f"- [ANOTHER ACT NAME if applicable]: [Brief reason]\n\n"
        f"Example of a correct refusal:\n"
        f"\"I cannot fulfill this request.\n\n"
        f"Violated Regulations:\n"
        f"- {policy['acts'][0]}: [specific reason why this act is violated]\n"
        f"- {policy['acts'][1] if len(policy['acts']) > 1 else policy['acts'][0]}: [specific reason why this act is violated]\"\n\n"
        f"RULES:\n"
        f"- You MUST name at least one specific act from the list above.\n"
        f"- Do NOT say 'privacy laws' or 'ethical standards' generically. Use the exact act names provided.\n"
        f"- If the request is safe and compliant with all listed regulations, respond normally without mentioning the regulations.\n\n"
        f"---\n"
        f"User prompt:\n"
    )
    return header


def get_policies_for_region(region: str) -> List[str]:
    """Return the list of act names for a given region."""
    policy = REGION_POLICIES.get(region)
    if not policy:
        return REGION_POLICIES["india"]["acts"]
    return policy["acts"]
