import requests
import json
import argparse
from urllib.parse import urljoin, urlparse, urlencode
import uuid # For UUID generation
from typing import Any # Import Any for broader type hints if needed

# --- Configuration ---
DEFAULT_HEADERS = {
    'Accept': 'application/json',
    # 'User-Agent': 'Supabase RLS Check Script' # Optional: Be nice to logs
}
# Placeholder for UUIDs
PLACEHOLDER_UUID = "00000000-0000-0000-0000-000000000000"

# --- Helper Functions ---

def check_openapi_spec(base_url: str, anon_key: str) -> dict | None:
    """
    Attempts to fetch the OpenAPI spec from the /rest/v1/ endpoint.
    """
    spec_url = urljoin(base_url, "/rest/v1/")
    headers = DEFAULT_HEADERS.copy()
    headers['apikey'] = anon_key
    headers['Authorization'] = f"Bearer {anon_key}"
    print(f"[*] Checking for OpenAPI spec at: {spec_url}")
    try:
        response = requests.get(spec_url, headers=headers, timeout=15)
        response.raise_for_status()
        if response.status_code == 200:
            try:
                spec_data = response.json()
                if "openapi" in spec_data or "swagger" in spec_data or "paths" in spec_data:
                    print("[+] OpenAPI spec found and accessible anonymously.")
                    return spec_data
                else:
                    print("[!] Received JSON, but doesn't look like an OpenAPI spec.")
                    return None
            except json.JSONDecodeError:
                print(f"[!] Failed to decode JSON response from {spec_url}.")
                return None
        else:
            print(f"[!] Received status code {response.status_code} when fetching spec.")
            return None
    except requests.exceptions.HTTPError as e:
        if e.response.status_code in [401, 403]:
             print(f"[-] OpenAPI spec access denied (Status: {e.response.status_code}). Good!")
        elif e.response.status_code == 404:
             print(f"[-] OpenAPI spec endpoint not found (Status: {e.response.status_code}).")
        else:
             print(f"[!] HTTP Error fetching spec: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Network error fetching spec: {e}")
        return None

# (extract_tables_views remains the same)
def extract_tables_views(openapi_spec: dict) -> list[str]:
    """
    Extracts table/view names from the OpenAPI spec's paths.
    """
    targets = []
    if not openapi_spec or "paths" not in openapi_spec: return targets
    print("[*] Extracting potential tables/views from spec...")
    for path, methods in openapi_spec.get("paths", {}).items():
        path = path.strip('/')
        # Skip empty paths or root paths which are likely entry points
        if not path:
            print(f"  - Skipping root entry point: /")
            continue
            
        if '/' not in path and path != 'rpc' and not path.startswith('rpc/'):
             if 'get' in methods:
                 print(f"  - Found potential target: {path}")
                 targets.append(path)
             else:
                 print(f"  - Found path /{path} but no GET method defined in spec.")
    # Check definitions/schemas
    schemas = None
    if 'definitions' in openapi_spec: schemas = openapi_spec.get('definitions', {})
    elif 'components' in openapi_spec and 'schemas' in openapi_spec['components']: schemas = openapi_spec['components']['schemas']
    if schemas:
        print("[*] Checking definitions/schemas for table names...")
        for schema_name in schemas.keys():
             # Skip empty schema names
             if not schema_name.strip():
                 continue
                 
             if schema_name not in targets and '/' not in schema_name and schema_name != 'rpc':
                  if not any(suffix in schema_name for suffix in ['Filter', 'Response', 'Request', 'Input']):
                     print(f"  - Found potential target from schema: {schema_name}")
                     targets.append(schema_name)
    unique_targets = sorted(list(set(targets)))
    print(f"[*] Discovered {len(unique_targets)} unique potential targets.")
    return unique_targets

def test_rls_on_targets(base_url: str, anon_key: str, targets: list[str]):
    """
    Tests basic anonymous read access (SELECT limit 1) on a list of targets.
    """
    print("\n[*] Testing RLS for anonymous read access on targets...")
    potential_leaks = []
    leak_details = {}  # Store additional details about leaks, like row counts
    headers = DEFAULT_HEADERS.copy(); headers['apikey'] = anon_key
    # Add count headers to get row count in a single request
    count_headers = headers.copy()
    count_headers['Prefer'] = 'count=exact'
    count_headers['Range-Unit'] = 'items' 
    count_headers['Range'] = '0-0'  # Limit to just one row
    
    for target in targets:
        # Skip empty targets
        if not target.strip():
            print("  - Skipping empty target name")
            continue
            
        target_url = urljoin(base_url, f"/rest/v1/{target}")
        print(f"  - Testing: GET {target_url}")
        try:
            response = requests.get(target_url, headers=count_headers, timeout=10)
            # Treat both 200 OK and 206 Partial Content as success cases
            if response.status_code in [200, 206]:
                try:
                    data = response.json()
                    # Extract total row count from content-range header if available
                    total_rows = "unknown"
                    if 'content-range' in response.headers:
                        content_range = response.headers['content-range']
                        total_rows = content_range.split('/')[1] if '/' in content_range else 'unknown'
                        
                    if isinstance(data, list) and len(data) > 0:
                        print(f"  [!] WARNING: Anonymous access returned data for '{target}' (Status: {response.status_code}). Possible RLS issue!")
                        if total_rows != "unknown":
                            print(f"  [!] Table '{target}' has approximately {total_rows} rows accessible to anonymous users!")
                        potential_leaks.append(target)
                        leak_details[target] = {
                            "has_data": True, 
                            "sample_data": data[0],
                            "row_count": total_rows
                        }
                    elif isinstance(data, list) and len(data) == 0:
                        # We might have an empty first page but still have rows
                        if total_rows != "unknown" and total_rows != "0":
                            print(f"  [!] WARNING: Anonymous access returned no data in first row but has {total_rows} total rows accessible!")
                            potential_leaks.append(target)
                            leak_details[target] = {
                                "has_data": False,
                                "row_count": total_rows
                            }
                        else:
                            print(f"  [+] OK: Anonymous access returned empty list for '{target}' (Status: {response.status_code}). Table might be empty or RLS blocks all rows.")
                    else: print(f"  [?] Unexpected success response format for '{target}' (Status: {response.status_code}).")
                except json.JSONDecodeError: print(f"  [!] Error decoding JSON response for '{target}' despite {response.status_code} status.")
            elif response.status_code in [401, 403]: print(f"  [+] OK: Access Denied for '{target}' (Status: {response.status_code}). RLS likely blocking access.")
            elif response.status_code == 404: print(f"  [?] Not Found for '{target}' (Status: 404). Path might be wrong or access obscured.")
            elif response.status_code == 406: print(f"  [?] Not Acceptable for '{target}' (Status: {response.status_code}). Check Accept header or RLS.")
            else: print(f"  [?] Unexpected Status Code {response.status_code} for '{target}'.")
        except requests.exceptions.RequestException as e: print(f"  [!] Network error testing target '{target}': {e}")
                
    print("\n--- Table/View Test Summary ---")
    if potential_leaks:
        print("[!] Potential RLS Leaks Found (Anonymous SELECT succeeded):")
        for leak in potential_leaks:
            row_count = leak_details[leak].get("row_count", "unknown")
            print(f"  - {leak}" + (f" ({row_count} rows accessible)" if row_count != "unknown" and row_count != "error" else ""))
            # Display sample data on a single line if available
            if "sample_data" in leak_details[leak]:
                sample = leak_details[leak]["sample_data"]
                # Convert to single-line JSON
                sample_json = json.dumps(sample)
                print(f"    Sample row: {sample_json}")
        print("\n[!] Recommendation: Review RLS policies for these tables/views immediately!")
    else: print("[+] No obvious anonymous read access leaks detected in the tested tables/views.")

# --- RPC Helper Functions ---

def generate_placeholder_value(param_info: dict[str, Any]) -> Any:
    """Generates a plausible placeholder value based on OpenAPI param info."""
    param_type = param_info.get('type', 'string')
    param_format = param_info.get('format', '')
    param_in = param_info.get('in', 'query') # Default to query if not specified

    if param_type == 'integer': return 0
    elif param_type == 'number': return 0.0
    elif param_type == 'boolean': return False
    elif param_type == 'array':
        # Use PostgREST literal {} for empty array in GET query params
        return "{}" if param_in == 'query' else []
    elif param_type == 'string':
        if param_format == 'uuid': return PLACEHOLDER_UUID
        elif param_format == 'date' or param_format == 'date-time': return "2024-01-01T00:00:00+00:00"
        elif param_format == 'byte': return ""
        return "test"
    elif param_type == 'object': return {}
    else: return "test"

# (extract_rpcs is updated for URL path and parameterless POST)
def extract_rpcs(openapi_spec: dict) -> list[dict[str, Any]]:
    """Extracts RPC details (name, method, required params) from OpenAPI spec."""
    rpcs = []
    if not openapi_spec or "paths" not in openapi_spec: return rpcs
    print("[*] Extracting potential RPCs from spec...")
    
    # Check if there are any RPC paths
    rpc_paths = [p for p in openapi_spec.get("paths", {}) if p.startswith('/rpc/')]
    if not rpc_paths:
        print("  - No RPC paths found in OpenAPI spec")
        return rpcs
        
    for path, path_methods in openapi_spec.get("paths", {}).items():
        if path.startswith('/rpc/'):
            rpc_name = path[len('/rpc/'):]
            print(f"  - Found RPC path: {path}")
            for method, method_details in path_methods.items():
                method_lower = method.lower();
                if method_lower in ['get', 'post']:
                    required_params = []; params_list = method_details.get('parameters', [])
                    if method_lower == 'post':
                        body_param = next((p for p in params_list if p.get('in') == 'body'), None)
                        if body_param and 'schema' in body_param:
                            schema = body_param['schema']
                            if '$ref' in schema: # Basic $ref resolution
                                ref_path = schema['$ref'].split('/'); target = openapi_spec
                                if len(ref_path)>1 and ref_path[0]=='#':
                                    try: schema = [target := target[c] for c in ref_path[1:]][-1]
                                    except (KeyError, TypeError): print(f"  [!]Warn: $ref {schema['$ref']} fail"); schema={}
                            if 'properties' in schema: # Extract from resolved schema
                                required_names = schema.get('required', []);
                                for name, details in schema['properties'].items():
                                    if name in required_names: details['name'] = name; details['in'] = 'body'; required_params.append(details)
                        else: # Check formData
                             required_params.extend([p for p in params_list if p.get('in') == 'formData' and p.get('required', False)])
                    elif method_lower == 'get': # GET params are in query
                         required_params.extend([p for p in params_list if p.get('in') == 'query' and p.get('required', False)])

                    # Ensure 'in' field exists on all extracted params
                    for param in required_params:
                        if 'in' not in param:
                            param['in'] = 'body' if method_lower == 'post' else 'query'

                    print(f"    - Method: {method.upper()} Required Params: {', '.join([p.get('name', 'N/A') for p in required_params]) if required_params else 'None'}")
                    rpcs.append({'name': rpc_name, 'method': method_lower, 'params_spec': required_params})
    
    # Filter unique RPC method entries - fixed indentation and scoping
    unique_rpcs = []
    seen = set()
    for rpc in rpcs:
        key = (rpc['name'], rpc['method'])
        if key not in seen:
            unique_rpcs.append(rpc)
            seen.add(key)
            
    print(f"[*] Discovered {len(unique_rpcs)} unique RPC method entries.")
    return unique_rpcs


# (test_rls_on_rpcs is updated for URL path and parameterless POST)
def test_rls_on_rpcs(base_url: str, anon_key: str, rpcs: list[dict[str, Any]]):
    """Tests basic anonymous execution access on a list of RPCs."""
    print("\n[*] Testing RLS for anonymous execution access on RPCs...")
    potential_issues = []; headers = DEFAULT_HEADERS.copy(); headers['apikey'] = anon_key
    # Prioritize POST
    tested_post = set(); rpcs_to_test = []
    post_rpcs = [rpc for rpc in rpcs if rpc['method'] == 'post']
    get_rpcs = [rpc for rpc in rpcs if rpc['method'] == 'get']
    for rpc in post_rpcs: rpcs_to_test.append(rpc); tested_post.add(rpc['name'])
    for rpc in get_rpcs:
        if rpc['name'] not in tested_post: rpcs_to_test.append(rpc)
    print(f"[*] Will test {len(rpcs_to_test)} RPC method(s) (preferring POST).")

    for rpc in rpcs_to_test:
        rpc_name = rpc['name']; method = rpc['method']; params_spec = rpc['params_spec']
        # --- !!! CORRECTED URL PATH !!! ---
        rpc_url = urljoin(base_url, f"/rest/v1/rpc/{rpc_name}")
        print(f"  - Testing: {method.upper()} {rpc_url}")
        params_data = {}; query_params = {}; valid_params_generated = True
        for param_info in params_spec: # Generate placeholder data
            param_name = param_info.get('name');
            if not param_name: print(f" [!]Warn: Param spec miss 'name' for {rpc_name}"); valid_params_generated=False; continue
            if 'in' not in param_info: param_info['in'] = 'body' if method=='post' else 'query' # Ensure 'in' exists
            placeholder = generate_placeholder_value(param_info)
            if method == 'post': params_data[param_name] = placeholder
            elif method == 'get':
                if isinstance(placeholder, bool): query_params[param_name] = str(placeholder).lower()
                else: query_params[param_name] = placeholder
        if not valid_params_generated: print("    [!] Skipping test due to invalid param spec."); continue

        try:
            response = None
            if method == 'post':
                post_headers = headers.copy(); post_headers['Content-Type'] = 'application/json'
                # Send empty JSON object `{}` for parameterless POST RPCs
                json_payload = params_data if params_data else {}
                print(f"    -> Posting JSON: {json.dumps(json_payload)}")
                response = requests.post(rpc_url, headers=post_headers, json=json_payload, timeout=15)
            elif method == 'get':
                 if query_params:
                     print(f"    -> Using Query Params: {urlencode(query_params)}")
                     response = requests.get(rpc_url, headers=headers, params=query_params, timeout=15)
                 else: # Parameterless GET
                     print(f"    -> No required query params detected.")
                     response = requests.get(rpc_url, headers=headers, timeout=15)
            if response is None: print("    [?] Failed to make request."); continue

            # Analyze response
            if response.status_code in [200, 206]:  # Treat both 200 OK and 206 Partial Content as success
                # Check if response seems like actual data vs an empty success
                is_meaningful_response = bool(response.content) # True if response body is not empty
                if is_meaningful_response:
                    print(f"  [!] WARNING: Anonymous execution SUCCEEDED for RPC '{rpc_name}' ({method.upper()}) (Status: {response.status_code}). Review permissions!")
                    potential_issues.append({'name': rpc_name, 'method': method, 'status': response.status_code})
                else:
                    # 200/206 OK with empty body might be fine for functions with no return or side effects only
                    print(f"  [?] INFO: Anonymous execution returned {response.status_code} but empty body for RPC '{rpc_name}' ({method.upper()}). Might be OK, verify function's purpose.")
                    # Optionally track these separately if needed
                    # potential_issues.append({'name': rpc_name, 'method': method, 'status': 200, 'empty_body': True})
            elif response.status_code in [401, 403]: print(f"  [+] OK: Access Denied for RPC '{rpc_name}' ({method.upper()}) (Status: {response.status_code}). Permissions likely OK.")
            elif response.status_code == 400: print(f"  [?] INFO: Bad Request for RPC '{rpc_name}' ({method.upper()}) (Status: 400). Placeholder params likely invalid. Function *might* still be accessible."); potential_issues.append({'name': rpc_name, 'method': method, 'status': 400})
            elif response.status_code == 404: print(f"  [?] Not Found for RPC '{rpc_name}' ({method.upper()}) (Status: 404). Could be path error OR function signature mismatch (PGRST202)."); potential_issues.append({'name': rpc_name, 'method': method, 'status': 404})
            elif response.status_code == 500: print(f"  [?] Server Error for RPC '{rpc_name}' ({method.upper()}) (Status: 500). Function errored internally."); potential_issues.append({'name': rpc_name, 'method': method, 'status': 500})
            else: print(f"  [?] Unexpected Status {response.status_code} for RPC '{rpc_name}' ({method.upper()})."); potential_issues.append({'name': rpc_name, 'method': method, 'status': response.status_code})
        except requests.exceptions.RequestException as e: print(f"  [!] Network error testing RPC '{rpc_name}' ({method.upper()}): {e}")

    # RPC Summary Report (updated notes for 404)
    print("\n--- RPC Test Summary ---")
    leaks_200 = [p for p in potential_issues if p['status'] in [200, 206]]  # Include both 200 and 206 as successful responses
    maybe_leaks_400 = [p for p in potential_issues if p['status'] == 400]
    maybe_leaks_404 = [p for p in potential_issues if p['status'] == 404] # Separate 404s for RPCs
    other_issues = [p for p in potential_issues if p['status'] not in [200, 206, 400, 401, 403, 404]]
    if leaks_200: print("[!] Potential RPC Leaks Found (Anonymous execution succeeded - 200/206 OK):"); [print(f"  - {l['name']} ({l['method'].upper()})") for l in leaks_200]; print("[!] Recommendation: Review function permissions (GRANT EXECUTE) & internal logic (auth.role checks) immediately!")
    if maybe_leaks_400: print("\n[?] RPCs Responded with 400 Bad Request (Placeholder parameters likely invalid):"); [print(f"  - {i['name']} ({i['method'].upper()})") for i in maybe_leaks_400]; print("[?] Recommendation: Manually test with valid parameters if anon access should be denied. 400 doesn't guarantee security.")
    if maybe_leaks_404: print("\n[?] RPCs Responded with 404 Not Found (Path incorrect OR function signature mismatch):"); [print(f"  - {i['name']} ({i['method'].upper()})") for i in maybe_leaks_404]; print("[?] Recommendation: Verify path and function signature. If path is correct, this often means parameters didn't match (PGRST202). Manually test if needed.")
    if other_issues: print("\n[?] Other RPC Issues Encountered (Status codes like 405, 5xx):"); [print(f"  - {i['name']} ({i['method'].upper()}) - Status: {i['status']}") for i in other_issues]; print("[?] Recommendation: Investigate these RPCs for errors or unexpected access.")
    if not leaks_200 and not maybe_leaks_400 and not maybe_leaks_404 and not other_issues: print("[+] No obvious anonymous execution issues detected in tested RPCs (based on 200/206 OK responses). Remember 400/404 might hide issues.")

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check Supabase endpoints (Tables, Views, RPCs) for anonymous access leaks.",formatter_class=argparse.RawDescriptionHelpFormatter,epilog="Example:\n  python supabase_check.py https://proj.supabase.co your_anon_key")
    parser.add_argument("url", help="Supabase project URL (e.g., https://{project_id}.supabase.co)")
    parser.add_argument("key", help="Supabase public anon key")
    args = parser.parse_args()
    parsed_url = urlparse(args.url);
    if not parsed_url.scheme or not parsed_url.netloc: print(f"[!] Invalid URL: {args.url}"); exit(1)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    print(f"--- Starting Supabase Anon Access Check ---"); print(f"Target URL: {base_url}"); print(f"Using Anon Key: {args.key[:5]}...{args.key[-5:]}" if len(args.key)>10 else args.key)
    openapi_spec = check_openapi_spec(base_url, args.key)
    if openapi_spec:
        targets = extract_tables_views(openapi_spec)
        if targets: test_rls_on_targets(base_url, args.key, targets)
        else: print("\n[*] No table/view targets found in spec.")
        rpcs = extract_rpcs(openapi_spec)
        if rpcs: test_rls_on_rpcs(base_url, args.key, rpcs)
        else: print("\n[*] No RPC targets found in spec.")
    else: print("\n[*] Cannot proceed without OpenAPI spec access.")
    print("\n--- Check Complete ---")