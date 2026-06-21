#!/usr/bin/env python3
import os
import sys
import json
import re

# Resolve paths relative to kin repo root
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KIN_ROOT = os.path.dirname(SCRIPT_DIR)
ALLOWLIST_PATH = os.path.join(SCRIPT_DIR, "zero-file-search-allowlist.json")

def load_allowlist():
    try:
        with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return {item["file"] for item in data.get("allowlist", [])}
    except Exception as e:
        print(f"Error loading allowlist from {ALLOWLIST_PATH}: {e}")
        sys.exit(1)

BOUNDARY_DIRS = [
    "crates/kin-daemon/",
    "crates/kin-migrate/",
    "crates/kin-index/",
    "crates/kin-registry/",
    "crates/kin-buildinfo/",
    "crates/kin-projection/",
    "crates/kin-reconcile/",
    "crates/kin-core/",
    "crates/kin-runtime/",
    "crates/kin-parser/",
    "crates/kin-ranking/src/ltr.rs",
    "crates/kin-cli/src/daemon_client.rs",
    "crates/kin-cli/src/profile.rs",
    "crates/kin-cli/src/main.rs",
    "crates/kin-cli/src/backend.rs"
]

QUERY_COMMANDS = {
    "locate.rs",
    "search.rs",
    "trace.rs",
    "trace_data_flow.rs",
    "xref.rs",
    "review.rs",
    "ref_lookup.rs"
}

def is_test_file(rel_path):
    # Skip standalone test directories
    if "tests/" in rel_path or "test_" in rel_path or rel_path.endswith("_test.rs"):
        return True
    # Skip ingestion/migration/daemon boundary directories/files
    for bdir in BOUNDARY_DIRS:
        if rel_path.startswith(bdir) or rel_path == bdir:
            return True
            
    # For CLI commands, only scan query commands
    if "crates/kin-cli/src/commands/" in rel_path:
        filename = os.path.basename(rel_path)
        if filename not in QUERY_COMMANDS:
            return True
            
    return False

# Patterns to scan
PATTERNS = [
    (re.compile(r'\bstd::fs::[a-zA-Z0-9_]+'), "std::fs API usage"),
    (re.compile(r'\bfs::(read|read_to_string|read_dir|write|copy|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all)\b'), "fs API usage"),
    (re.compile(r'\bwalkdir::WalkDir\b'), "walkdir usage"),
    (re.compile(r'Command::new\("git"\).*?"grep"'), "git grep subprocess usage")
]

def scan_file(filepath, rel_path):
    violations = []
    
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
        
    in_block_comment = False
    in_test_module = False
    brace_depth = 0
    test_module_brace_depth = -1
    
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Track block comments
        if "/*" in stripped:
            in_block_comment = True
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
            
        # Ignore single line comments
        if stripped.startswith("//"):
            continue
            
        # Remove trailing comments
        if "//" in line:
            line = line.split("//")[0]
            stripped = line.strip()
            
        # Track test module to ignore test code inside source files
        if "mod tests" in stripped or "#[cfg(test)]" in stripped:
            in_test_module = True
            test_module_brace_depth = brace_depth
            
        # Track brace depth
        brace_depth += stripped.count("{") - stripped.count("}")
        
        if in_test_module and brace_depth <= test_module_brace_depth:
            in_test_module = False
            test_module_brace_depth = -1
            
        if in_test_module:
            continue
            
        # Skip attributes like #[test]
        if stripped.startswith("#[test]"):
            continue
            
        # Scan for patterns
        for pattern, desc in PATTERNS:
            if pattern.search(line):
                violations.append((idx, line.strip(), desc))
                
    return violations

def main():
    allowlist = load_allowlist()
    total_violations = 0
    
    # Walk crates directory
    crates_dir = os.path.join(KIN_ROOT, "crates")
    if not os.path.exists(crates_dir):
        print(f"Error: crates directory not found at {crates_dir}")
        sys.exit(1)
        
    for root, _, files in os.walk(crates_dir):
        for file in files:
            if not file.endswith(".rs"):
                continue
                
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, KIN_ROOT)
            
            # Skip test files and allowed files
            if is_test_file(rel_path):
                continue
            if rel_path in allowlist:
                continue
                
            violations = scan_file(filepath, rel_path)
            if violations:
                print(f"\n[VIOLATION] {rel_path} contains forbidden filesystem access:")
                for line_num, content, desc in violations:
                    print(f"  Line {line_num:4d}: {content} ({desc})")
                total_violations += len(violations)
                
    if total_violations > 0:
        print(f"\nVerification FAILED: Found {total_violations} zero-file-search violations.")
        sys.exit(1)
        
    print("Verification PASSED: Zero File-Search Invariant holds.")
    sys.exit(0)

if __name__ == "__main__":
    main()
