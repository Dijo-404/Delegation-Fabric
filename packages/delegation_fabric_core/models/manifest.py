"""Agent manifest domain model."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class RiskClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MemoryPolicy(BaseModel):
    classes: list[str] = Field(default_factory=list)
    ttl_days: int = 30
    prohibited_content: list[str] = Field(
        default_factory=lambda: ["bank_account", "secret", "execution_grant"]
    )


class CapabilityDeclaration(BaseModel):
    """A declared capability (tool) an agent may request authorization for."""

    tool: str
    allowed_fields: list[str] = Field(default_factory=list)
    requires_approval: bool = False


class AgentManifest(BaseModel):
    """Versioned declaration of an agent's capabilities, risk and region.

    This is the authoritative source for what an agent CAN request.
    The Control Plane checks this before issuing any Execution Grant.
    """

    agent_id: str
    version: str
    display_name: str = ""
    owner: str = ""
    risk_class: RiskClass = RiskClass.MEDIUM

    capabilities: list[str] = Field(
        default_factory=list,
        description="Tools the agent may be authorized to use",
    )
    denied_tools: list[str] = Field(
        default_factory=list,
        description="Tools explicitly forbidden regardless of delegation",
    )

    allowed_regions: list[str] = Field(default_factory=list)
    memory: MemoryPolicy = Field(default_factory=MemoryPolicy)

    def can_request_tool(self, tool: str) -> bool:
        """Check if agent may request authorization for this tool."""
        if tool in self.denied_tools:
            return False
        return tool in self.capabilities
