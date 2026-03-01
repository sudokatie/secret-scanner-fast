#!/bin/bash
# Install secret-scanner-fast as a git pre-commit hook
# Usage: ./install-hook.sh [--global]

set -e

HOOK_CONTENT='#!/bin/sh
# secret-scanner-fast pre-commit hook
# Installed by: scripts/install-hook.sh

# Scan only staged files for speed
secret-scanner-fast scan --staged

if [ $? -ne 0 ]; then
    echo ""
    echo "Secrets detected! Commit blocked."
    echo "If these are false positives, add them to .secretscanner.yaml allowlist:"
    echo ""
    echo "rules:"
    echo "  allowlist:"
    echo "    - pattern: \"your-pattern-here\""
    echo "      reason: \"Explanation\""
    echo ""
    exit 1
fi
'

install_hook() {
    local hooks_dir="$1"
    local hook_path="${hooks_dir}/pre-commit"
    
    mkdir -p "$hooks_dir"
    
    if [ -f "$hook_path" ]; then
        echo "Warning: pre-commit hook already exists at $hook_path"
        echo "Appending secret-scanner-fast check..."
        
        # Check if already installed
        if grep -q "secret-scanner-fast" "$hook_path"; then
            echo "secret-scanner-fast already installed in this hook."
            return 0
        fi
        
        # Append to existing hook
        echo "" >> "$hook_path"
        echo "# secret-scanner-fast check" >> "$hook_path"
        echo 'secret-scanner-fast scan --staged || exit 1' >> "$hook_path"
    else
        echo "$HOOK_CONTENT" > "$hook_path"
    fi
    
    chmod +x "$hook_path"
    echo "Installed pre-commit hook at $hook_path"
}

if [ "$1" = "--global" ]; then
    # Global hook template
    template_dir=$(git config --global init.templateDir 2>/dev/null || echo "")
    
    if [ -z "$template_dir" ]; then
        template_dir="$HOME/.git-templates"
        git config --global init.templateDir "$template_dir"
        echo "Set global template directory to $template_dir"
    fi
    
    install_hook "${template_dir}/hooks"
    echo ""
    echo "Global hook installed. New repos will include secret scanning."
    echo "To add to existing repos, run: git init (safe to re-run)"
else
    # Local repo hook
    if [ ! -d ".git" ]; then
        echo "Error: not in a git repository"
        exit 1
    fi
    
    install_hook ".git/hooks"
fi
