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


def build_governance_system_instruction(region: str) -> str:
    """
    Internal system instructions for chat (not shown to the user).
    Models must follow these rules silently unless they must refuse.
    """
    policy = REGION_POLICIES.get(region) or REGION_POLICIES["india"]
    acts_list = "\n".join(f"  - {act}" for act in policy["acts"])

    return (
        f"[Governance — region: {region.upper()} — internal only, do not repeat to the user]\n"
        f"Follow these regulations when answering:\n{acts_list}\n\n"
        f"{policy['summary']}\n\n"
        f"CRITICAL — user-visible reply rules:\n"
        f"- Answer the user's question directly. Do NOT add a compliance statement, regulatory summary, "
        f"or 'I can fulfill this request' line.\n"
        f"- Do NOT mention NITI Aayog, DPDPA, GDPR, PIPL, or other act names unless you are refusing.\n"
        f"- Do NOT list which laws apply when the request is allowed — apply them silently.\n"
        f"- Only if you must refuse, use exactly:\n"
        f"  I cannot fulfill this request.\n\n"
        f"  Violated Regulations:\n"
        f"  - [exact act name]: [brief reason]\n"
    )


def build_compliance_header(region: str) -> str:
    """
    Legacy prepend for analyze API: governance block + user prompt label.
    """
    return build_governance_system_instruction(region) + "\n---\nUser prompt:\n"


def get_policies_for_region(region: str) -> List[str]:
    """Return the list of act names for a given region."""
    policy = REGION_POLICIES.get(region)
    if not policy:
        return REGION_POLICIES["india"]["acts"]
    return policy["acts"]
