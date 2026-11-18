"""Default confidential-business categories for the hybrid sensitive detector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .sensitive import Action, SensitiveCategory, SensitiveSettings


def _category(
    category_id: str,
    description: str,
    *labels: str,
    gliner: float = 0.6,
    semantic: float = 0.75,
    require_both: bool = True,
    action: Action = "BLOCK",
) -> SensitiveCategory:
    return SensitiveCategory(
        category_id=category_id,
        description=description,
        entity_labels=tuple(labels),
        gliner_threshold=gliner,
        semantic_threshold=semantic,
        require_both=require_both,
        input_action=action,
        output_action=action,
    )


DEFAULT_SENSITIVE_SETTINGS = SensitiveSettings(
    categories=(
        _category("CORPORATE_FINANCIAL_DATA", "Non-public corporate revenue, profit margins, financial forecasts, budgets and cash flow projections.", "internal revenue forecast", "confidential profit margin", "non-public budget amount", "private cash flow projection", gliner=0.75, semantic=0.5, require_both=False),
        _category("BUSINESS_STRATEGY", "Non-public business plans, expansion plans, market strategies and competitive strategies.", "confidential business plan", "unannounced expansion market", "private competitive strategy"),
        _category("INTELLECTUAL_PROPERTY", "Non-public trade secrets, proprietary algorithms, patents under development and technical designs.", "trade secret", "proprietary algorithm", "unpublished patent invention", "confidential technical design"),
        _category("PROPRIETARY_SOURCE_CODE", "Private application source code, proprietary libraries, unpublished code and internal source repositories.", "proprietary source code", "private repository name", "internal library name", "confidential code snippet"),
        _category("PRODUCT_CONFIDENTIALITY", "Unreleased products, non-public product roadmaps, upcoming features and launch plans.", "unreleased product name", "confidential product roadmap", "unannounced feature", "private launch date"),
        _category("INTERNAL_PROJECT_INFORMATION", "Confidential internal project plans, project codenames, internal milestones and project status.", "confidential project codename", "internal project milestone", "internal project status", gliner=0.5),
        _category("CUSTOMER_CONFIDENTIAL_INFORMATION", "Confidential customer contracts, negotiated pricing, customer purchase history and commercial arrangements.", "confidential customer contract information", "negotiated customer pricing", "customer purchase history", gliner=0.5, semantic=0.5),
        _category("VENDOR_SUPPLIER_INFORMATION", "Confidential supplier contracts, vendor pricing, procurement terms and vendor evaluations.", "confidential supplier contract", "negotiated vendor pricing", "procurement terms", "vendor evaluation"),
        _category("EMPLOYEE_HR_CONFIDENTIALITY", "Confidential salary structures, compensation bands, appraisals, workforce planning and disciplinary records.", "employee compensation information", "salary band", "performance appraisal", "disciplinary record", gliner=0.5),
        _category("LEGAL_CONFIDENTIALITY", "Privileged legal advice, litigation strategy, privileged documents and confidential agreements.", "privileged legal advice", "litigation strategy", "privileged document", "confidential agreement"),
        _category("MERGERS_AND_ACQUISITIONS", "Undisclosed acquisition targets, merger plans, due diligence reports and deal valuations.", "undisclosed acquisition target", "merger plan", "due diligence report", "deal valuation"),
        _category("SALES_CONFIDENTIALITY", "Non-public sales pipeline, deal strategy, discount approvals and customer negotiations.", "sales pipeline", "unannounced enterprise deal", "discount approval", "customer negotiation"),
        _category("MARKETING_CONFIDENTIALITY", "Unreleased marketing campaigns, advertising budgets, launch strategies and internal market research.", "unreleased campaign", "advertising budget", "launch strategy", "internal market research"),
        _category("OPERATIONAL_CONFIDENTIALITY", "Internal standard operating procedures, business continuity plans and restricted operational processes.", "internal standard operating procedure", "business continuity plan", "restricted operational process"),
        _category("CLOUD_COST_FINOPS", "Internal cloud expenditure, negotiated cloud rates, optimization savings and cost allocation models.", "negotiated cloud rate", "internal cloud spend", "cost optimization savings", "cost allocation model"),
        _category("INFRASTRUCTURE_ARCHITECTURE", "Internal network topology, architecture diagrams, system dependencies and internal service endpoints.", "internal network topology", "architecture diagram", "system dependency map", "internal service endpoint"),
        _category("SECURITY_ARCHITECTURE", "Internal security architecture, access controls, vulnerability reports and incident response plans.", "internal security policy", "security assessment report", "vulnerability report", "incident response plan"),
        _category("CONFIGURATION_INFORMATION", "Non-public internal configuration, deployment topology and system settings.", "internal deployment configuration", "deployment topology", "internal system setting"),
        _category("DATA_SCIENCE_AI_ASSETS", "Proprietary datasets, model weights, training datasets, evaluation datasets and internal prompts.", "proprietary dataset", "model weights", "training dataset", "evaluation dataset", "internal system prompt"),
        _category("AI_GOVERNANCE_INFORMATION", "Internal model evaluation results, AI risk assessments, model-routing policies and governance strategies.", "internal model evaluation result", "AI risk assessment", "model routing policy", "AI governance strategy"),
        _category("RESEARCH_AND_DEVELOPMENT", "Unpublished experimental results, research findings, prototypes and unreleased inventions.", "unpublished experimental result", "unpublished research finding", "unreleased prototype", "unreleased invention"),
        _category("GOVERNMENT_CLASSIFIED_INFORMATION", "Restricted government documents, classified material and export-controlled technical information.", "restricted government document", "classified material", "export-controlled technical information"),
        _category("INTERNAL_COMMUNICATIONS", "Confidential internal emails, management discussions and internal meeting notes.", "confidential internal email", "confidential management discussion", "internal meeting notes"),
        _category("RISK_AND_AUDIT_INFORMATION", "Internal audit findings, risk assessments, compliance gaps and control weaknesses.", "internal audit finding", "internal risk assessment", "compliance gap", "control weakness"),
        _category("PRICING_AND_COMMERCIAL_INFORMATION", "Internal pricing models, discount structures, margins and negotiation limits.", "internal pricing model", "discount structure", "confidential margin", "negotiation limit"),
        _category("INTELLECTUAL_BUSINESS_DOCUMENTS", "Proprietary reports, internal presentations and restricted business documentation.", "proprietary report", "confidential board presentation", "restricted business document"),
    )
)


def load_sensitive_settings(path: str | Path | None = None) -> SensitiveSettings:
    if path is None:
        return DEFAULT_SENSITIVE_SETTINGS
    data: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
    categories = tuple(
        SensitiveCategory(
            category_id=str(item["category_id"]),
            description=str(item["description"]),
            entity_labels=tuple(str(label) for label in item["entity_labels"]),
            gliner_threshold=float(item.get("gliner_threshold", 0.6)),
            semantic_threshold=float(item.get("semantic_threshold", 0.75)),
            require_both=bool(item.get("require_both", True)),
            input_action=str(item.get("input_action", "BLOCK")),  # type: ignore[arg-type]
            output_action=str(item.get("output_action", "BLOCK")),  # type: ignore[arg-type]
        )
        for item in data["categories"]
    )
    return SensitiveSettings(
        categories=categories,
        fail_closed=bool(data.get("fail_closed", True)),
        max_chars=int(data.get("max_chars", 20_000)),
        chunk_chars=int(data.get("chunk_chars", 700)),
    )
