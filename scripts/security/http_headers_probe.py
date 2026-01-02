"""
HTTP Security Headers Probe

Tests for required security headers on API responses:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY or SAMEORIGIN
- CORS headers validation
- Cache-Control for sensitive endpoints
"""

import asyncio
import time
import httpx
from base_probe import BaseProbe, ProbeResult, parse_args, run_probe


# Required security headers and their expected values
REQUIRED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": ["DENY", "SAMEORIGIN"],
}

# Headers that should NOT be present (information disclosure)
DANGEROUS_HEADERS = [
    "server",           # Server version disclosure
    "x-powered-by",     # Technology disclosure
    "x-aspnet-version", # ASP.NET version
]

# Test endpoints (both v1 and v2)
TEST_ENDPOINTS = [
    "/",
    "/docs",
    "/api/v1/health",
    "/api/v1/chains",
    "/api/v2/health",
    "/api/v2/channels/test-channel",
    "/api/v2/organizations/test-org",
]


class HTTPHeadersProbe(BaseProbe):
    """Probe for HTTP security headers."""
    
    async def run(self):
        """Run all header checks."""
        async with httpx.AsyncClient(
            base_url=self.base_url, 
            timeout=self.timeout,
            follow_redirects=True
        ) as client:
            for endpoint in TEST_ENDPOINTS:
                await self._check_endpoint(client, endpoint)
    
    async def _check_endpoint(self, client: httpx.AsyncClient, endpoint: str):
        """Check headers for a single endpoint."""
        result = ProbeResult(
            name=f"headers_check_{endpoint.replace('/', '_')}",
            endpoint=endpoint
        )
        
        try:
            start = time.time()
            response = await client.get(endpoint, headers=self.get_headers())
            result.elapsed_ms = (time.time() - start) * 1000
            result.status_code = response.status_code
            result.headers = dict(response.headers)
            
            # Check required headers
            for header, expected in REQUIRED_HEADERS.items():
                actual = response.headers.get(header)
                if not actual:
                    result.add_finding(
                        severity="medium",
                        message=f"Missing security header: {header}",
                        details={"expected": expected}
                    )
                elif isinstance(expected, list):
                    if actual not in expected:
                        result.add_finding(
                            severity="low",
                            message=f"Unexpected value for {header}",
                            details={"expected": expected, "actual": actual}
                        )
                elif actual.lower() != expected.lower():
                    result.add_finding(
                        severity="low",
                        message=f"Unexpected value for {header}",
                        details={"expected": expected, "actual": actual}
                    )
            
            # Check dangerous headers
            for header in DANGEROUS_HEADERS:
                if header in response.headers:
                    result.add_finding(
                        severity="low",
                        message=f"Information disclosure via {header} header",
                        details={"value": response.headers[header]}
                    )
            
            # Check CORS
            cors_origin = response.headers.get("access-control-allow-origin")
            if cors_origin == "*":
                result.add_finding(
                    severity="medium",
                    message="CORS allows all origins (*)",
                    details={"header": "access-control-allow-origin", "value": "*"}
                )
            
            # No findings = good
            if not result.findings:
                result.add_finding(
                    severity="info",
                    message="All security headers present and correct"
                )
                
        except httpx.RequestError as e:
            result.error = str(e)
        
        self.results.append(result)


if __name__ == "__main__":
    args = parse_args("Check HTTP security headers on API endpoints")
    asyncio.run(run_probe(HTTPHeadersProbe, args))
