"""
NeuroBots OpenAPI (Swagger) Spec Auto-Discovery & Policy Import Engine.

Parses OpenAPI v3.0 / Swagger v2.0 JSON or YAML contracts, auto-extracts
protected routes, path parameters, and generates updated route definitions.
"""

import json
from typing import Dict, Any, List


def parse_openapi_spec(spec_data: Dict[str, Any]) -> Dict[str, Any]:
    """Parses OpenAPI spec object and produces route definitions for routes.json."""
    paths = spec_data.get("paths", {})
    new_routes = []
    discovered_endpoints = 0

    for path_template, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, details in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                continue

            discovered_endpoints += 1
            # Infer resource type from path (e.g. /api/accounts/{id} -> account)
            segments = [s for s in path_template.strip("/").split("/") if s]
            resource_type = "account"
            if "transfers" in segments:
                resource_type = "transfer"
            elif "admin" in segments:
                resource_type = "admin"

            # Check if path has object ID parameter
            has_id = any("{" in s and "}" in s for s in segments)

            route_entry = {
                "method": method.upper(),
                "prefix": path_template.split("{")[0].rstrip("/"),
                "resource": resource_type,
                "require_ownership": has_id and resource_type != "admin",
                "required_roles": ["admin"] if resource_type == "admin" else ["user"],
                "description": details.get("summary") or details.get("description") or f"OpenAPI Auto-Discovered Route {method.upper()} {path_template}",
            }
            new_routes.append(route_entry)

    return {
        "status": "success",
        "title": spec_data.get("info", {}).get("title", "Imported API Spec"),
        "version": spec_data.get("info", {}).get("version", "1.0.0"),
        "discovered_endpoints": discovered_endpoints,
        "routes": new_routes,
    }
