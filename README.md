# Supabase REST Sniffer

A security auditing tool for Supabase projects that checks for potential data exposure through anonymous API access. It tests your Supabase REST API endpoints and functions for proper Row Level Security (RLS) configuration.

## Why Use This?

- **Verify RLS policies** are properly protecting your data
- **Discover exposed tables and views** accessible to unauthenticated users
- **Test RPC function security** to prevent unauthorized access
- **Identify configuration issues** before they become security problems

## Quick Start

```bash
python main.py https://your_project_ref.supabase.co your_public_anon_key_here
```

## Requirements

- Python 3.10+
- `requests` library (see requirements.txt)

## How It Works

The tool:
1. Fetches your project's OpenAPI spec to discover available endpoints
2. Attempts anonymous access to tables, views, and stored procedures
3. Reports potential security issues

## Output

The tool provides a comprehensive security report showing:
- Tables/views with potentially misconfigured RLS policies
- RPC functions that can be executed without authentication
- Detailed explanations of each finding and its security implications

## Security Note

This tool only requires your public anon key (which is safe to share) and helps you proactively identify security issues before malicious actors can exploit them.