"""Pydantic schemas for LLM-generated remediation guidance."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StepByStepRemediation(BaseModel):
    step_number: int
    title: str
    description: str
    commands_or_code: str | None = None
    verification: str

    model_config = ConfigDict(from_attributes=True)


class RemediationSchema(BaseModel):
    source: Literal["llm", "fallback", "unknown"] = "unknown"
    fallback_reason: str | None = None
    summary: str
    root_cause: str
    business_impact: str
    prerequisites: list[str] = Field(default_factory=list)
    remediation_steps: list[StepByStepRemediation] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
