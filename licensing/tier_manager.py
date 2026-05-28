"""
Tier Manager — Feature Flags per License Tier
==============================================
Maps license tiers to allowed pipelines and resource limits.
"""

from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

# ── Tier Definitions ──────────────────────────────────────────────────────────

# Default tier → pipeline mapping
DEFAULT_TIER_PIPELINES: Dict[str, List[str]] = {
    "standard": [
        "text_analysis",
    ],
    "professional": [
        "text_analysis",
        "data_enrichment",
    ],
    "enterprise": [
        "text_analysis",
        "data_enrichment",
        "full_research",
    ],
}

# Default tier → resource limits
DEFAULT_TIER_LIMITS: Dict[str, Dict] = {
    "standard": {
        "max_concurrent_pipelines": 1,
        "max_models": 1,
        "vector_db_access": False,
        "max_steps_per_pipeline": 5,
    },
    "professional": {
        "max_concurrent_pipelines": 3,
        "max_models": 2,
        "vector_db_access": True,
        "max_steps_per_pipeline": 10,
    },
    "enterprise": {
        "max_concurrent_pipelines": 10,
        "max_models": 5,
        "vector_db_access": True,
        "max_steps_per_pipeline": 50,
    },
}


class TierManager:
    """Manages feature flags and pipeline access by license tier."""

    def __init__(
        self,
        tier_pipelines: Optional[Dict[str, List[str]]] = None,
        tier_limits: Optional[Dict[str, Dict]] = None,
    ):
        self.tier_pipelines = tier_pipelines or DEFAULT_TIER_PIPELINES
        self.tier_limits = tier_limits or DEFAULT_TIER_LIMITS

    def get_allowed_pipelines(self, tier: str) -> List[str]:
        """Return list of pipelines allowed for the given tier."""
        pipelines = self.tier_pipelines.get(tier, [])
        logger.debug(f"Tier '{tier}' allowed pipelines: {pipelines}")
        return pipelines

    def is_pipeline_allowed(self, tier: str, pipeline: str) -> bool:
        """Check if a specific pipeline is allowed for the tier."""
        allowed = pipeline in self.get_allowed_pipelines(tier)
        if not allowed:
            logger.warning(
                f"Pipeline '{pipeline}' is NOT allowed for tier '{tier}'. "
                f"Allowed: {self.get_allowed_pipelines(tier)}"
            )
        return allowed

    def get_limits(self, tier: str) -> Dict:
        """Return resource limits for the given tier."""
        return self.tier_limits.get(tier, self.tier_limits["standard"])

    def get_all_tiers(self) -> List[str]:
        """Return all available tier names."""
        return list(self.tier_pipelines.keys())

    def get_tier_summary(self, tier: str) -> Dict:
        """Return a full summary of the tier's capabilities."""
        return {
            "tier": tier,
            "pipelines": self.get_allowed_pipelines(tier),
            "limits": self.get_limits(tier),
        }
