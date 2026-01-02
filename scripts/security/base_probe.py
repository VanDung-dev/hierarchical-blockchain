"""
Base template for security probe scripts.

Provides common utilities for all security testing scripts:
- Argument parsing (--base-url, --api-key, --output)
- Async HTTP client setup
- JSON result formatting and logging
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Any


class ProbeResult:
    """Container for individual probe results."""
    
    def __init__(self, name: str, endpoint: str):
        self.name = name
        self.endpoint = endpoint
        self.status_code: int | None = None
        self.headers: dict[str, str] = {}
        self.findings: list[dict[str, Any]] = []
        self.error: str | None = None
        self.elapsed_ms: float = 0
    
    def add_finding(self, severity: str, message: str, details: dict | None = None):
        """Add a security finding.
        
        Args:
            severity: One of 'critical', 'high', 'medium', 'low', 'info'
            message: Brief description of the finding
            details: Optional additional details
        """
        self.findings.append({
            "severity": severity,
            "message": message,
            "details": details or {}
        })
    
    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "endpoint": self.endpoint,
            "status_code": self.status_code,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "findings": self.findings,
            "error": self.error
        }


class BaseProbe:
    """Base class for security probe scripts."""
    
    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.results: list[ProbeResult] = []
        self.start_time = datetime.now()
    
    def get_headers(self, include_api_key: bool = True) -> dict[str, str]:
        """Get default headers for requests."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if include_api_key and self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers
    
    async def run(self):
        """Run all probes. Override this in subclasses."""
        raise NotImplementedError("Subclasses must implement run()")
    
    def get_report(self) -> dict[str, Any]:
        """Generate final report."""
        all_findings = []
        for result in self.results:
            all_findings.extend(result.findings)
        
        # Count by severity
        severity_counts = {}
        for finding in all_findings:
            sev = finding["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "probe_type": self.__class__.__name__,
            "base_url": self.base_url,
            "timestamp": self.start_time.isoformat(),
            "summary": {
                "total_tests": len(self.results),
                "total_findings": len(all_findings),
                "by_severity": severity_counts
            },
            "results": [r.to_dict() for r in self.results]
        }
    
    def print_report(self, output_file: str | None = None):
        """Print report to stdout or file."""
        report = self.get_report()
        json_output = json.dumps(report, indent=2, ensure_ascii=False)
        
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"[+] Report saved to: {output_file}", file=sys.stderr)
        else:
            print(json_output)


def parse_args(description: str) -> argparse.Namespace:
    """Parse common command line arguments."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--base-url", 
        default="http://127.0.0.1:2661",
        help="Base URL of the API server (default: http://127.0.0.1:2661)"
    )
    parser.add_argument(
        "--api-key",
        help="API key for authentication (optional)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for JSON report (default: stdout)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10)"
    )
    return parser.parse_args()


async def run_probe(probe_class, args: argparse.Namespace):
    """Run a probe class with parsed arguments."""
    probe = probe_class(
        base_url=args.base_url,
        api_key=args.api_key,
        timeout=args.timeout
    )
    await probe.run()
    probe.print_report(args.output)
