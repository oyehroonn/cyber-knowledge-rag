"""
RAG Pipeline for Cybersecurity Testing Platform

This module provides a complete RAG (Retrieval-Augmented Generation) pipeline
for security vulnerability analysis, hypothesis generation, and finding verification.
"""

from llm.llm_client import (
    call_llm,
    summarize_finding,
    generate_attack_hypothesis,
    suggest_test_cases,
)

__all__ = [
    "call_llm",
    "summarize_finding",
    "generate_attack_hypothesis",
    "suggest_test_cases",
]

__version__ = "1.0.0"
