"""
LLM Client - Drop-in Replacement

This module provides the exact function signatures expected by the main application.
It wraps the RAG engine to provide context-aware security analysis.

FUNCTION SIGNATURES (DO NOT MODIFY):
- call_llm(prompt: str, context: list[str] = []) -> str
- summarize_finding(finding_dict: dict) -> str
- generate_attack_hypothesis(intel_dict: dict) -> str
- suggest_test_cases(object_model: dict, permission_matrix: dict) -> list[str]
"""

import json
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

# Lazy-loaded singleton instances
_rag_engine = None
_initialized = False


def _get_rag_engine():
    """Get or create the RAG engine singleton."""
    global _rag_engine, _initialized
    
    if _rag_engine is None:
        try:
            import os
            from llm.rag_engine import RAGEngine
            from llm.model_selector import ModelSelector

            # Only check Ollama if not using DeepSeek API
            use_deepseek_api = bool(os.environ.get("DEEPSEEK_API_KEY", "").strip())
            if not use_deepseek_api:
                selector = ModelSelector()
                if not selector.check_ollama_running():
                    console.print("[yellow]Warning: Ollama not running. LLM features will be limited.[/yellow]")
                    console.print("[dim]Start Ollama with: ollama serve — or set DEEPSEEK_API_KEY in .env to use DeepSeek API.[/dim]")
            else:
                console.print("[dim]Using DeepSeek API (DEEPSEEK_API_KEY is set)[/dim]")

            # Initialize RAG engine (uses DeepSeek API if key set, else Ollama)
            data_dir = Path(__file__).parent / "data"
            _rag_engine = RAGEngine(data_dir=data_dir)
            _initialized = True

        except Exception as e:
            console.print(f"[red]Error initializing RAG engine: {e}[/red]")
            _rag_engine = None

    return _rag_engine


def _fallback_response(prompt: str, context: list[str] = None) -> str:
    """Generate a fallback response when LLM is unavailable."""
    context_note = f" with {len(context)} context items" if context else ""
    return f"""[LLM Unavailable]

Unable to process request{context_note}. Please ensure one of:
• DeepSeek API: set DEEPSEEK_API_KEY in .env (get key at https://platform.deepseek.com)
• Or local Ollama: install (https://ollama.ai), run 'ollama serve', then 'ollama pull deepseek-r1:14b'

Original prompt summary: {prompt[:200]}{'...' if len(prompt) > 200 else ''}
"""


# =============================================================================
# PUBLIC API - These function signatures MUST match the main app's expectations
# =============================================================================


def call_llm(prompt: str, context: list[str] = None) -> str:
    """
    Call the LLM with a prompt and optional context.
    
    This is the primary interface for the main application to interact with the LLM.
    Context is automatically retrieved from the knowledge base if not provided.
    
    Args:
        prompt: The user prompt/query
        context: Optional list of context strings to include
        
    Returns:
        LLM response string
    """
    if context is None:
        context = []
    
    engine = _get_rag_engine()
    
    if engine is None:
        return _fallback_response(prompt, context)
    
    try:
        # If no context provided, retrieve relevant context from vector store
        if not context:
            context = engine.retrieve_context(prompt, n=5)
        
        # Build the full prompt with context
        if context:
            context_section = "\n\n## Relevant Context\n\n"
            for i, ctx in enumerate(context, 1):
                context_section += f"### Context {i}\n{ctx}\n\n"
            full_prompt = f"{context_section}\n## Query\n\n{prompt}"
        else:
            full_prompt = prompt
        
        # Call LLM
        response = engine._call_llm_with_retry(
            full_prompt,
            system_prompt=engine._get_system_prompt()
        )
        
        return response
        
    except Exception as e:
        console.print(f"[red]LLM error: {e}[/red]")
        return _fallback_response(prompt, context)


def summarize_finding(finding_dict: dict) -> str:
    """
    Summarize a security finding into a concise report.
    
    Args:
        finding_dict: Dictionary containing finding details:
            - title: Finding title
            - type/vuln_class: Vulnerability type
            - severity: Severity level
            - description: Finding description
            - evidence: Supporting evidence
            - affected_component: What's affected
            
    Returns:
        Markdown-formatted summary string
    """
    engine = _get_rag_engine()
    
    if engine is None:
        return _format_finding_fallback(finding_dict)
    
    try:
        # Generate full report using RAG
        report = engine.write_finding_report(finding_dict)
        return report
        
    except Exception as e:
        console.print(f"[red]Error summarizing finding: {e}[/red]")
        return _format_finding_fallback(finding_dict)


def _format_finding_fallback(finding_dict: dict) -> str:
    """Format a finding without LLM assistance."""
    title = finding_dict.get("title", "Security Finding")
    vuln_type = finding_dict.get("type", finding_dict.get("vuln_class", "Unknown"))
    severity = finding_dict.get("severity", "Unknown")
    description = finding_dict.get("description", "No description provided")
    
    return f"""# {title}

**Vulnerability Type**: {vuln_type}
**Severity**: {severity}

## Description

{description}

## Details

```json
{json.dumps(finding_dict, indent=2)}
```

---
*Note: Full analysis unavailable - LLM not connected*
"""


def generate_attack_hypothesis(intel_dict: dict) -> str:
    """
    Generate attack hypotheses from intelligence/recon data.
    
    Args:
        intel_dict: Dictionary containing reconnaissance data:
            - endpoints: Discovered endpoints
            - parameters: Found parameters
            - auth_mechanisms: Authentication methods
            - technologies: Detected technologies
            - behaviors: Observed behaviors
            
    Returns:
        String containing attack hypotheses (may contain JSON structure)
    """
    engine = _get_rag_engine()
    
    if engine is None:
        return _format_hypothesis_fallback(intel_dict)
    
    try:
        # Use RAG engine to analyze recon data
        analysis = engine.analyze_recon(intel_dict)
        
        # Format the response
        if isinstance(analysis, dict):
            if "raw_analysis" in analysis:
                return analysis["raw_analysis"]
            
            # Format structured analysis
            output_parts = []
            
            if "summary" in analysis:
                output_parts.append(f"## Analysis Summary\n\n{analysis['summary']}")
            
            if "attack_vectors" in analysis:
                output_parts.append("\n## Attack Vectors\n")
                for av in analysis["attack_vectors"]:
                    output_parts.append(f"""
### {av.get('name', 'Unknown Attack')}
- **Type**: {av.get('vulnerability_class', 'Unknown')}
- **Likelihood**: {av.get('likelihood', 'Unknown')}
- **Impact**: {av.get('impact', 'Unknown')}

{av.get('description', '')}

**Test Approach**:
{chr(10).join('- ' + step for step in av.get('test_approach', []))}
""")
            
            if "high_risk_areas" in analysis:
                output_parts.append("\n## High Risk Areas\n")
                for area in analysis["high_risk_areas"]:
                    output_parts.append(f"- **{area.get('area', 'Unknown')}** ({area.get('risk_level', 'Unknown')}): {area.get('reasoning', '')}")
            
            return "\n".join(output_parts)
        
        return str(analysis)
        
    except Exception as e:
        console.print(f"[red]Error generating hypothesis: {e}[/red]")
        return _format_hypothesis_fallback(intel_dict)


def _format_hypothesis_fallback(intel_dict: dict) -> str:
    """Format hypothesis without LLM assistance."""
    endpoints = intel_dict.get("endpoints", [])
    params = intel_dict.get("parameters", [])
    
    hypotheses = []
    
    # Generate basic hypotheses based on data patterns
    if endpoints:
        if any("user" in str(e).lower() or "account" in str(e).lower() for e in endpoints):
            hypotheses.append("- **IDOR Hypothesis**: User-related endpoints may allow unauthorized access to other users' data")
        if any("admin" in str(e).lower() for e in endpoints):
            hypotheses.append("- **Privilege Escalation Hypothesis**: Admin endpoints may be accessible without proper authorization")
        if any("api" in str(e).lower() for e in endpoints):
            hypotheses.append("- **API Security Hypothesis**: API endpoints may lack proper authentication or rate limiting")
    
    if params:
        if any("id" in str(p).lower() for p in params):
            hypotheses.append("- **Parameter Tampering Hypothesis**: ID parameters may be vulnerable to manipulation")
        if any("url" in str(p).lower() or "redirect" in str(p).lower() for p in params):
            hypotheses.append("- **SSRF/Open Redirect Hypothesis**: URL parameters may allow server-side request forgery")
    
    if not hypotheses:
        hypotheses.append("- Unable to generate specific hypotheses without LLM analysis")
    
    return f"""# Attack Hypotheses

Based on the provided intelligence data:

{chr(10).join(hypotheses)}

## Raw Intelligence

```json
{json.dumps(intel_dict, indent=2, default=str)}
```

---
*Note: Full analysis unavailable - LLM not connected*
"""


def suggest_test_cases(object_model: dict, permission_matrix: dict) -> list[str]:
    """
    Suggest security test cases based on application model.
    
    Args:
        object_model: Dictionary describing application objects/entities:
            - objects: List of entity types
            - relationships: How entities relate
            - actions: Available operations
            
        permission_matrix: Dictionary describing access control:
            - roles: User roles
            - permissions: What each role can do
            - resources: Protected resources
            
    Returns:
        List of test case strings
    """
    engine = _get_rag_engine()
    
    if engine is None:
        return _generate_test_cases_fallback(object_model, permission_matrix)
    
    try:
        # Generate hypotheses using RAG
        hypotheses = engine.generate_hypotheses(object_model, permission_matrix)
        
        # Extract test cases from hypotheses
        test_cases = []
        
        for hyp in hypotheses:
            if isinstance(hyp, dict):
                # Extract test procedure
                test_procedure = hyp.get("test_procedure", [])
                if test_procedure:
                    title = hyp.get("title", "Security Test")
                    vuln_class = hyp.get("vulnerability_class", "Unknown")
                    
                    # Format as test case string
                    test_case = f"[{vuln_class}] {title}\n"
                    test_case += "Steps:\n"
                    for i, step in enumerate(test_procedure, 1):
                        test_case += f"  {i}. {step}\n"
                    
                    expected = hyp.get("expected_outcome", {})
                    if isinstance(expected, dict):
                        test_case += f"Expected (if vulnerable): {expected.get('if_vulnerable', 'N/A')}\n"
                    
                    test_cases.append(test_case)
            elif isinstance(hyp, str):
                test_cases.append(hyp)
        
        # If no test cases extracted, return raw hypotheses
        if not test_cases and hypotheses:
            if isinstance(hypotheses[0], dict) and "raw_hypotheses" in hypotheses[0]:
                return [hypotheses[0]["raw_hypotheses"]]
        
        return test_cases if test_cases else _generate_test_cases_fallback(object_model, permission_matrix)
        
    except Exception as e:
        console.print(f"[red]Error suggesting test cases: {e}[/red]")
        return _generate_test_cases_fallback(object_model, permission_matrix)


def _generate_test_cases_fallback(object_model: dict, permission_matrix: dict) -> list[str]:
    """Generate basic test cases without LLM assistance."""
    test_cases = []
    
    # Extract objects and roles
    objects = object_model.get("objects", list(object_model.keys()))
    roles = permission_matrix.get("roles", list(permission_matrix.keys()))
    
    # Generate generic IDOR tests
    for obj in objects[:5]:  # Limit to first 5 objects
        test_cases.append(
            f"[IDOR] Test access control for {obj}\n"
            f"Steps:\n"
            f"  1. Authenticate as User A\n"
            f"  2. Create/access a {obj} resource\n"
            f"  3. Note the resource ID\n"
            f"  4. Authenticate as User B\n"
            f"  5. Attempt to access User A's {obj} using the ID\n"
            f"Expected: Access should be denied"
        )
    
    # Generate privilege escalation tests
    if len(roles) >= 2:
        low_role = roles[-1] if roles else "user"
        high_role = roles[0] if roles else "admin"
        test_cases.append(
            f"[Privilege Escalation] Test {low_role} to {high_role} escalation\n"
            f"Steps:\n"
            f"  1. Authenticate as {low_role}\n"
            f"  2. Identify {high_role}-only functions\n"
            f"  3. Attempt to call {high_role} functions directly\n"
            f"  4. Check for parameter tampering (role/permission fields)\n"
            f"Expected: {high_role} functions should be inaccessible"
        )
    
    # Add generic security tests
    test_cases.extend([
        "[Authentication] Test session management\n"
        "Steps:\n"
        "  1. Login and capture session token\n"
        "  2. Logout\n"
        "  3. Attempt to use old session token\n"
        "Expected: Old tokens should be invalidated",
        
        "[Input Validation] Test for injection vulnerabilities\n"
        "Steps:\n"
        "  1. Identify input fields\n"
        "  2. Test with special characters: ' \" < > { } | \\\n"
        "  3. Test SQL injection payloads\n"
        "  4. Test XSS payloads\n"
        "Expected: Input should be properly sanitized",
        
        "[Business Logic] Test workflow integrity\n"
        "Steps:\n"
        "  1. Identify multi-step processes\n"
        "  2. Attempt to skip steps\n"
        "  3. Attempt to repeat steps\n"
        "  4. Attempt to go backwards in workflow\n"
        "Expected: Workflow should enforce proper sequence",
    ])
    
    return test_cases


# =============================================================================
# Utility functions for main app integration
# =============================================================================


def get_status() -> dict:
    """Get the status of the LLM subsystem."""
    from llm.model_selector import ModelSelector
    from llm.vector_store.chroma_store import ChromaStore
    
    data_dir = Path(__file__).parent / "data"
    
    selector = ModelSelector()
    selector.get_available_models()
    selector.select_best_model()
    
    store = ChromaStore(data_dir)
    
    return {
        "ollama_installed": selector.check_ollama_installed(),
        "ollama_running": selector.check_ollama_running(),
        "available_models": selector.available_models,
        "selected_model": selector.selected_model,
        "total_chunks": store.get_total_chunks(),
        "initialized": _initialized,
    }


def initialize() -> bool:
    """
    Initialize the LLM subsystem.
    
    Returns:
        True if initialization successful, False otherwise
    """
    engine = _get_rag_engine()
    return engine is not None


if __name__ == "__main__":
    # Test the client functions
    console.print("[bold]Testing LLM Client Functions[/bold]\n")
    
    # Test status
    status = get_status()
    console.print("[cyan]Status:[/cyan]")
    for key, value in status.items():
        console.print(f"  {key}: {value}")
    
    # Test call_llm
    console.print("\n[cyan]Testing call_llm...[/cyan]")
    response = call_llm("What are common IDOR vulnerability patterns?")
    console.print(f"Response preview: {response[:200]}...")
    
    # Test summarize_finding
    console.print("\n[cyan]Testing summarize_finding...[/cyan]")
    finding = {
        "title": "IDOR in User Profile API",
        "type": "IDOR",
        "severity": "high",
        "description": "User can access other users' profiles by changing the user_id parameter",
    }
    summary = summarize_finding(finding)
    console.print(f"Summary preview: {summary[:300]}...")
    
    # Test generate_attack_hypothesis
    console.print("\n[cyan]Testing generate_attack_hypothesis...[/cyan]")
    intel = {
        "endpoints": ["/api/users/{id}", "/api/admin/users", "/api/account/settings"],
        "parameters": ["user_id", "role", "redirect_url"],
    }
    hypothesis = generate_attack_hypothesis(intel)
    console.print(f"Hypothesis preview: {hypothesis[:300]}...")
    
    # Test suggest_test_cases
    console.print("\n[cyan]Testing suggest_test_cases...[/cyan]")
    object_model = {"objects": ["User", "Order", "Payment"]}
    permissions = {"roles": ["admin", "user", "guest"]}
    test_cases = suggest_test_cases(object_model, permissions)
    console.print(f"Generated {len(test_cases)} test cases")
    if test_cases:
        console.print(f"First test case: {test_cases[0][:200]}...")
