#!/usr/bin/env python3
import sys
import json
import subprocess
import os
import shutil
import argparse
from datetime import datetime

def run_sqlmap(target, scan_type, output_file):
    """
    Run SQLMap scan
    """
    start_time = datetime.now()
    results = {
        "tool": "sqlmap",
        "target": target,
        "scan_type": scan_type,
        "timestamp": start_time.isoformat(),
        "vulnerabilities": []
    }

    # Check if sqlmap is installed
    if not shutil.which("sqlmap"):
        results["error"] = "SQLMap not installed"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        return

    # Prepare command
    # Using --batch for non-interactive mode
    # Using --forms to parse forms
    # Using --crawl=1 for quick crawl
    cmd = ["sqlmap", "-u", target, "--batch", "--random-agent", "--output-dir=/tmp/sqlmap_out"]
    
    if scan_type == 'quick':
        cmd.extend(["--level=1", "--risk=1"])
    else:
        cmd.extend(["--level=2", "--risk=2"])

    try:
        # Run sqlmap
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        # Parse logic would go here - for now taking stdout/stderr
        # SQLMap output is complex to parse into JSON directly without proper flags
        # We will look for keywords in stdout
        
        if "is vulnerable" in process.stdout:
            results["vulnerabilities"].append({
                "type": "SQL Injection",
                "severity": "Critical",
                "description": "SQLMap found potential injection points",
                "raw_output": process.stdout[-500:] # Last 500 chars
            })
        
        results["raw_stdout"] = process.stdout
        results["duration"] = (datetime.now() - start_time).total_seconds()
        
    except subprocess.TimeoutExpired:
        results["error"] = "Scan timed out"
    except Exception as e:
        results["error"] = str(e)

    # Save results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("scan_type")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    run_sqlmap(args.target, args.scan_type, args.output)
