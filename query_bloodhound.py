#!/usr/bin/env python3
"""
Utility script to execute Cypher queries against BloodHound for debugging.
"""

import argparse
import json
import os
import sys
from bloodhound_client import BloodHoundClient


def format_results(data: dict) -> str:
    """Format query results for display."""
    if not data.get("data"):
        return "No results returned"

    result_data = data.get("data", {}).get("data", [])

    if not result_data:
        return "Query executed successfully but returned no data"

    # Pretty print the results
    return json.dumps(result_data, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Execute Cypher queries against BloodHound",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Execute a simple query
  python query_bloodhound.py -u http://localhost:8080 -k YOUR_API_KEY \\
    -q "MATCH (n:K8sServiceAccount) RETURN n.name LIMIT 5"

  # Execute query from file
  python query_bloodhound.py -u http://localhost:8080 -k YOUR_API_KEY \\
    -f my_query.cypher

  # Use username/password instead of API key
  python query_bloodhound.py -u http://localhost:8080 \\
    --username admin --password password \\
    -q "MATCH (n) RETURN count(n)"
        """
    )

    # Connection options
    parser.add_argument("-u", "--url", "--bloodhound-url",
                        default=os.environ.get("BLOODHOUND_URL"),
                        help="BloodHound server URL (e.g., http://localhost:8080) [env: BLOODHOUND_URL]")

    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument("-k", "--api-key",
                           default=os.environ.get("BLOODHOUND_API_KEY"),
                           help="BloodHound API key (JWT token) [env: BLOODHOUND_API_KEY]")
    auth_group.add_argument("--username",
                           default=os.environ.get("BLOODHOUND_USERNAME"),
                           help="BloodHound username (requires --password) [env: BLOODHOUND_USERNAME]")

    parser.add_argument("--password",
                       default=os.environ.get("BLOODHOUND_PASSWORD"),
                       help="BloodHound password (use with --username) [env: BLOODHOUND_PASSWORD]")

    # Query options
    query_group = parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument("-q", "--query",
                            help="Cypher query string to execute")
    query_group.add_argument("-f", "--file",
                            help="File containing Cypher query")

    parser.add_argument("--no-properties",
                       action="store_true",
                       help="Don't include node/relationship properties in results")

    parser.add_argument("--raw",
                       action="store_true",
                       help="Output raw JSON response")

    args = parser.parse_args()

    if not args.url:
        parser.error("-u/--url or BLOODHOUND_URL is required")
    if not args.api_key and not args.username:
        parser.error("one of -k/--api-key or --username (or BLOODHOUND_API_KEY / BLOODHOUND_USERNAME) is required")

    # Validate username/password combination
    if args.username and not args.password:
        print("Error: --password is required when using --username")
        sys.exit(1)

    # Create BloodHound client
    if args.api_key:
        client = BloodHoundClient(args.url, args.api_key)
    else:
        print(f"Logging in to BloodHound as {args.username}...")
        client = BloodHoundClient.from_credentials(args.url, args.username, args.password)
        if not client:
            print("Error: Failed to authenticate with BloodHound")
            sys.exit(1)

    # Get query from file or command line
    if args.file:
        try:
            with open(args.file, 'r') as f:
                query = f.read().strip()
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    else:
        query = args.query

    # Execute query
    print(f"\nExecuting query:")
    print(f"  {query[:100]}{'...' if len(query) > 100 else ''}\n")

    result = client.execute_cypher_query(query, include_properties=not args.no_properties)

    # Display results
    if result.get("success"):
        if args.raw:
            print(json.dumps(result["data"], indent=2))
        else:
            print("Query executed successfully!\n")
            print(format_results(result))
    else:
        print(f"Query failed: {result.get('error')}")
        if "details" in result:
            print(f"\nDetails:")
            if isinstance(result["details"], list):
                for error in result["details"]:
                    if isinstance(error, dict):
                        print(f"  - {error.get('message', str(error))}")
                    else:
                        print(f"  - {error}")
            else:
                print(f"  {result['details']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
