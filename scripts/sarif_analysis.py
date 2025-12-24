"""
SARIF Analysis Script

This script parses a SARIF (Static Analysis Results Interchange Format) file 
and prints out the analysis results in a readable format.

Usage:
    python scripts/sarif_analysis.py [sarif_file]
    
If no file is specified, defaults to 'python.sarif'.
"""

import json
import sys
import os


def analyze_sarif(sarif_file: str) -> None:
    """Parse and display SARIF analysis results."""
    if not os.path.exists(sarif_file):
        print(f"Info: SARIF file '{sarif_file}' not found.")
        print("\nTo generate a SARIF file, run a static analysis tool with SARIF output.")
        print("Example with pylint:")
        print("  pylint hierachain --output-format=sarif > python.sarif")
        print("\nNo analysis performed.")
        return  # Exit gracefully, not an error
    
    try:
        with open(sarif_file, 'r', encoding='utf-8') as f:
            sarif = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in SARIF file: {e}")
        sys.exit(1)
    
    total_results = 0
    for run in sarif.get('runs', []):
        tool_name = run.get('tool', {}).get('driver', {}).get('name', 'Unknown')
        results = run.get('results', [])
        
        if results:
            print(f"\n=== {tool_name} ({len(results)} findings) ===\n")
            
        for r in results:
            locations = r.get('locations', [])
            if locations:
                loc = locations[0].get('physicalLocation', {})
                uri = loc.get('artifactLocation', {}).get('uri', 'unknown')
                line = loc.get('region', {}).get('startLine', '?')
                rule_id = r.get('ruleId', 'unknown')
                message = r.get('message', {}).get('text', 'No message')
                level = r.get('level', 'note')
                
                print(f"[{level.upper()}] {rule_id}")
                print(f"  File: {uri}:{line}")
                print(f"  Message: {message}")
                print()
                total_results += 1
    
    if total_results == 0:
        print("No findings in SARIF file.")
    else:
        print(f"\nTotal findings: {total_results}")


if __name__ == "__main__":
    sarif_file = sys.argv[1] if len(sys.argv) > 1 else 'python.sarif'
    analyze_sarif(sarif_file)
