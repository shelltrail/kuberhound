"""
BloodHound API client for uploading graph data.
Handles the 3-step job-based upload workflow.
"""

import json
import os
import time
import requests
from typing import Dict, Any, List, Callable, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Data files shipped next to this module, so the tool works from any working directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CUSTOM_NODES_FILE = os.path.join(BASE_DIR, "CustomNodes.json")
DEFAULT_QUERIES_FILE = os.path.join(BASE_DIR, "kuberhound_queries.json")

# File upload job statuses (BloodHound's JobStatus)
JOB_COMPLETE = 2
JOB_PARTIALLY_COMPLETE = 8
JOB_FINAL_STATUSES = {2: "complete", 3: "canceled", 4: "timed out", 5: "failed", 8: "partially complete"}

# How long to wait for BloodHound's data pipeline (purge, ingest, analysis) before giving up
DATAPIPE_TIMEOUT_SECONDS = 900


def _new_session() -> requests.Session:
    """HTTP session reusing connections and retrying rate-limited (429) requests with backoff."""
    session = requests.Session()
    # Only 429 responses are retried: the request was rejected, so re-sending (even a POST) is safe
    retry = Retry(total=5, connect=0, read=0, other=0, status_forcelist=[429], allowed_methods=None,
                  backoff_factor=0.5, respect_retry_after_header=True, raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


class BloodHoundClient:
    """Client for interacting with BloodHound CE API."""

    def __init__(self, base_url: str, api_key: str):
        """
        Initialize BloodHound client.

        Args:
            base_url: BloodHound server URL (e.g., http://localhost:8080)
            api_key: JWT Bearer token for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.session = _new_session()
        self.session.headers["Authorization"] = f"Bearer {api_key}"

    @classmethod
    def from_credentials(cls, base_url: str, username: str, password: str):
        """
        Create BloodHound client by logging in with username and password.

        Args:
            base_url: BloodHound server URL (e.g., http://localhost:8080)
            username: BloodHound username
            password: BloodHound password

        Returns:
            BloodHoundClient instance if login successful, None otherwise
        """
        base_url = base_url.rstrip('/')
        payload = {
            "login_method": "secret",
            "secret": password,
            "username": username
        }

        try:
            response = requests.post(f"{base_url}/api/v2/login", json=payload, timeout=30)
        except requests.exceptions.RequestException as e:
            print(f"Error: Failed to connect to BloodHound server: {e}")
            return None

        if response.status_code == 401:
            print("Error: Authentication failed - invalid username or password")
            return None
        if response.status_code != 200:
            print(f"Error: Login failed (status {response.status_code})")
            print(f"Response: {response.text}")
            return None

        session_token = response.json().get("data", {}).get("session_token")
        if not session_token:
            print("Error: No session token in response")
            return None

        print(f"Successfully logged in as {username}")
        return cls(base_url, session_token)

    def _url(self, path: str) -> str:
        return f"{self.base_url}/api/v2/{path}"

    def register_custom_nodes(self, custom_nodes_file: str = DEFAULT_CUSTOM_NODES_FILE) -> bool:
        """
        Register custom node types with BloodHound to enable custom icons.
        Node types that are already registered are left unchanged.

        Args:
            custom_nodes_file: Path to CustomNodes.json file

        Returns:
            True if registration successful, False otherwise
        """
        try:
            with open(custom_nodes_file, 'r') as f:
                our_node_types = json.load(f).get("custom_types", {})

            register_url = self._url("custom-nodes")

            # Find which node types are already registered
            existing_node_kinds = set()
            try:
                list_response = self.session.get(register_url, timeout=30)
                if list_response.status_code == 200:
                    existing_node_kinds = {t.get("kindName") for t in list_response.json().get("data", [])}
            except Exception as e:
                print(f"  Warning: Could not fetch existing custom nodes: {e}")

            new_types = [t for t in our_node_types if t not in existing_node_kinds]
            existing_count = len(our_node_types) - len(new_types)
            if existing_count:
                print(f"  Already registered: {existing_count} node type(s)")

            if not new_types:
                print("  All custom node types already registered")
                return True

            print(f"  Registering {len(new_types)} new node type(s)...")
            fail_count = 0
            for node_type in new_types:
                response = self.session.post(
                    register_url, json={"custom_types": {node_type: our_node_types[node_type]}}, timeout=30
                )
                if response.status_code not in (200, 201):
                    fail_count += 1
                    print(f"    Failed to register {node_type}: {response.status_code}")

            success_count = len(new_types) - fail_count
            if success_count:
                print(f"  Successfully registered {success_count} new custom node type(s)")
            if fail_count:
                print(f"  Warning: {fail_count} node type(s) failed to register")
                return False
            return True

        except FileNotFoundError:
            print(f"Warning: {custom_nodes_file} not found. Skipping custom node registration.")
            return False
        except Exception as e:
            print(f"Warning: Failed to register custom nodes: {e}")
            return False

    def upload_graph(self, graph: Dict[str, Any], filename: str = "kuberhound_data.json") -> bool:
        """
        Upload graph data to BloodHound using the job-based workflow.

        Workflow:
        1. Create a file upload job (POST /api/v2/file-upload/start)
        2. Upload file to the job (POST /api/v2/file-upload/{job_id})
        3. End the upload job (POST /api/v2/file-upload/{job_id}/end)

        Args:
            graph: OpenGraph JSON structure
            filename: Name to give the uploaded file

        Returns:
            True if upload successful, False otherwise
        """
        try:
            job_id = self._create_upload_job()
            if not job_id:
                return False

            if not self._upload_file(job_id, graph, filename):
                return False

            if not self._end_upload_job(job_id):
                print("Warning: Failed to end upload job, but data was uploaded")
                return True

            return self._wait_for_upload_job(job_id)

        except requests.exceptions.ConnectionError:
            print(f"Error: Could not connect to BloodHound at {self.base_url}")
            print("Make sure BloodHound is running and the URL is correct.")
            return False
        except requests.exceptions.Timeout:
            print("Error: Request timed out")
            return False
        except requests.exceptions.RequestException as e:
            print(f"Error uploading to BloodHound: {e}")
            return False
        except (KeyError, ValueError) as e:
            print(f"Error parsing BloodHound API response: {e}")
            return False

    def _create_upload_job(self):
        """
        Create a new file upload job.

        Returns:
            Job ID if successful, None otherwise
        """
        print(f"Creating upload job at {self.base_url}...")
        response = self.session.post(self._url("file-upload/start"), timeout=30)

        if response.status_code == 401:
            print("Error: Authentication failed. Check your API key.")
            return None
        if response.status_code != 201:
            print(f"Error: Failed to create upload job (status {response.status_code})")
            print(f"Response: {response.text}")
            return None

        job_id = response.json().get("data", {}).get("id")
        if not job_id:
            print("Error: No job ID returned from start endpoint")
            print(f"Response: {response.text}")
            return None

        print(f"Created upload job with ID: {job_id}")
        return job_id

    def _upload_file(self, job_id: int, graph: Dict[str, Any], filename: str) -> bool:
        """
        Upload file data to an existing upload job.

        Args:
            job_id: Upload job ID
            graph: OpenGraph JSON structure
            filename: Filename for error reporting

        Returns:
            True if successful, False otherwise
        """
        print(f"Uploading {filename}...")
        response = self.session.post(
            self._url(f"file-upload/{job_id}"),
            headers={"Content-Type": "application/json", "X-File-Upload-Name": filename},
            data=json.dumps(graph).encode('utf-8'),
            timeout=60
        )

        if response.status_code == 401:
            print("Error: Authentication failed during upload.")
            return False
        if response.status_code == 404:
            print(f"Error: Upload job {job_id} not found.")
            return False
        if response.status_code != 202:
            print(f"Error: File upload failed (status {response.status_code})")
            print(f"Response: {response.text}")
            return False

        print("File uploaded successfully")
        return True

    def _end_upload_job(self, job_id: int) -> bool:
        """
        Finalize an upload job.

        Args:
            job_id: Upload job ID

        Returns:
            True if successful, False otherwise
        """
        print("Finalizing upload job...")
        response = self.session.post(self._url(f"file-upload/{job_id}/end"), timeout=30)

        if response.status_code != 200:
            print(f"Warning: Failed to end upload job (status {response.status_code})")
            print(f"Response: {response.text}")
            return False

        return True

    def _delete_all(self, list_path: str, extract_items: Callable[[Dict], List[Dict]], noun: str) -> bool:
        """
        List items at an endpoint and delete each one (DELETE {list_path}/{id}).

        Args:
            list_path: API path under /api/v2 listing the items
            extract_items: Returns the item list from the listing's JSON response
            noun: Item description for messages, e.g. "saved quer(y/ies)"

        Returns:
            True if every item was deleted, False otherwise
        """
        list_url = self._url(list_path)
        try:
            response = self.session.get(f"{list_url}?skip=0&limit=1000",
                                        headers={"Accept": "application/json"}, timeout=30)
            if response.status_code == 401:
                print("Error: Authentication failed. Check your API key.")
                return False
            if response.status_code != 200:
                print(f"Warning: Failed to fetch {noun} (status {response.status_code})")
                return False

            items = extract_items(response.json())
            if not items:
                print(f"  No {noun} to clear")
                return True

            print(f"  Found {len(items)} {noun} to delete")
            failed_count = 0
            for item in items:
                name = item.get("name", "Unknown")
                delete_response = self.session.delete(f"{list_url}/{item.get('id')}", timeout=30)
                if delete_response.status_code in (200, 204):
                    print(f"  ✓ Deleted: {name}")
                else:
                    print(f"  ✗ Failed to delete: {name} (status {delete_response.status_code})")
                    failed_count += 1

            print(f"\nCleared {len(items) - failed_count} {noun}")
            if failed_count:
                print(f"Warning: {failed_count} {noun} failed to delete")
            return failed_count == 0

        except requests.exceptions.RequestException as e:
            print(f"Error clearing {noun} at {self.base_url}: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error clearing {noun}: {e}")
            return False

    def clear_owned_selectors(self, owned_tag_id: int = 2) -> bool:
        """
        Clear all selectors from the "Owned" asset group tag.
        This removes all marked "Owned" nodes before ingesting new data.

        Args:
            owned_tag_id: Asset group tag ID for "Owned" (default: 2)

        Returns:
            True if successful, False otherwise
        """
        print(f"Clearing all 'Owned' selectors (tag ID: {owned_tag_id})...")
        return self._delete_all(f"asset-group-tags/{owned_tag_id}/selectors",
                                lambda data: data.get("data", {}).get("selectors", []),
                                "'Owned' selector(s)")

    def clear_saved_queries(self) -> bool:
        """
        Clear all saved queries from BloodHound.
        This will delete all custom queries created by the current user.

        Returns:
            True if successful, False otherwise
        """
        print("Clearing all saved queries from BloodHound...")
        return self._delete_all("saved-queries", lambda data: data.get("data", []), "saved quer(y/ies)")

    def clear_database(self, clear_owned: bool = True, clear_queries: bool = True) -> bool:
        """
        Clear the BloodHound database before importing new data.
        This deletes collected graph data, file ingest history, and data quality history.
        Optionally clears all "Owned" asset group selectors and saved queries.

        Args:
            clear_owned: Whether to also clear "Owned" selectors (default: True)
            clear_queries: Whether to also clear all saved queries (default: True)

        Returns:
            True if successful, False otherwise
        """
        if clear_queries and not self.clear_saved_queries():
            print("Warning: Failed to clear some saved queries, but continuing with database clear")

        if clear_owned and not self.clear_owned_selectors():
            print("Warning: Failed to clear some 'Owned' selectors, but continuing with database clear")

        # Deletion is queued and carried out by the data pipeline, so note its state first
        baseline = self._wait_for_datapipe_idle()
        if baseline is not None:
            baseline = baseline.get("last_complete_analysis_at")

        print(f"\nClearing BloodHound database at {self.base_url}...")
        payload = {
            "deleteCollectedGraphData": True,
            "deleteFileIngestHistory": True,
            "deleteDataQualityHistory": True,
            "deleteAssetGroupSelectors": [0]
        }

        try:
            response = self.session.post(
                self._url("clear-database"),
                headers={"accept": "text/plain", "Prefer": "wait=30"},
                json=payload,
                timeout=60
            )
        except requests.exceptions.RequestException as e:
            print(f"Error clearing database at {self.base_url}: {e}")
            return False

        if response.status_code in (200, 204):
            return self._wait_for_purge(baseline)
        if response.status_code == 401:
            print("Error: Authentication failed. Check your API key.")
        elif response.status_code == 403:
            print("Error: Insufficient permissions to clear database.")
        else:
            print(f"Error: Failed to clear database (status {response.status_code})")
            print(f"Response: {response.text}")
        return False

    def _datapipe_status(self) -> Optional[Dict[str, Any]]:
        """Current data pipeline status (status, last_complete_analysis_at, ...), or None if unavailable."""
        try:
            response = self.session.get(self._url("datapipe/status"), timeout=30)
            if response.status_code == 200:
                return response.json().get("data")
        except (requests.exceptions.RequestException, ValueError):
            pass
        return None

    def _wait_for_datapipe_idle(self) -> Optional[Dict[str, Any]]:
        """Wait until the data pipeline is idle; returns its status, or None if it can't be read."""
        deadline = time.monotonic() + DATAPIPE_TIMEOUT_SECONDS
        status = self._datapipe_status()
        while status is not None and status.get("status") != "idle" and time.monotonic() < deadline:
            time.sleep(5)
            status = self._datapipe_status()
        return status

    def _wait_for_purge(self, baseline: Optional[str]) -> bool:
        """
        Wait until the data pipeline has carried out the queued deletion. It is done once the
        pipeline is idle again after having been seen purging or having completed a new analysis
        (it analyses the emptied graph right after purging).
        """
        print("Waiting for BloodHound to delete the data...")
        deadline = time.monotonic() + DATAPIPE_TIMEOUT_SECONDS
        seen_purging = False
        while time.monotonic() < deadline:
            status = self._datapipe_status()
            if status is None:
                print("Warning: Could not read BloodHound's data pipeline status; wait at least 30 seconds before ingesting new data")
                return True
            state = status.get("status")
            seen_purging = seen_purging or state == "purging"
            if state == "idle" and (seen_purging or status.get("last_complete_analysis_at") != baseline):
                print("Database cleared successfully")
                return True
            time.sleep(2)

        print(f"Error: BloodHound did not finish deleting the data within {DATAPIPE_TIMEOUT_SECONDS} seconds")
        return False

    def _wait_for_upload_job(self, job_id: int) -> bool:
        """Wait until BloodHound has processed an upload job; True if its data was ingested."""
        print("Waiting for BloodHound to ingest the data...")
        deadline = time.monotonic() + DATAPIPE_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            try:
                response = self.session.get(self._url("file-upload?sort_by=-id&limit=50"), timeout=30)
                jobs = response.json().get("data", []) if response.status_code == 200 else []
            except (requests.exceptions.RequestException, ValueError):
                jobs = []
            job = next((j for j in jobs if j.get("id") == job_id), None)

            if job and job.get("status") in JOB_FINAL_STATUSES:
                status = job["status"]
                if status == JOB_COMPLETE:
                    print("Successfully uploaded data to BloodHound!")
                    return True
                message = f": {job['status_message']}" if job.get("status_message") else ""
                if status == JOB_PARTIALLY_COMPLETE:
                    print(f"Warning: Upload job {job_id} was only partially ingested{message}")
                    return True
                print(f"Error: Upload job {job_id} was {JOB_FINAL_STATUSES[status]}{message}")
                return False
            time.sleep(5)

        print(f"Error: Upload job {job_id} was not ingested within {DATAPIPE_TIMEOUT_SECONDS} seconds")
        return False

    def execute_cypher_query(self, query: str, include_properties: bool = True) -> Dict[str, Any]:
        """
        Execute a Cypher query against the BloodHound graph database.

        Args:
            query: Cypher query string to execute
            include_properties: Whether to include node/relationship properties in results

        Returns:
            Dictionary containing query results and metadata, or error information
        """
        try:
            response = self.session.post(
                self._url("graphs/cypher"),
                headers={"accept": "application/json", "Prefer": "wait=30"},
                json={"query": query, "include_properties": include_properties},
                timeout=60
            )
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": f"Could not connect to BloodHound at {self.base_url}"}
        except requests.exceptions.Timeout:
            return {"success": False, "error": "Query timed out (exceeded 60 seconds)"}
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"Request error: {e}"}

        try:
            return self._cypher_result(response)
        except ValueError as e:
            return {"success": False, "error": f"Unexpected error: {e}"}

    @staticmethod
    def _cypher_result(response: requests.Response) -> Dict[str, Any]:
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        if response.status_code == 400:
            return {
                "success": False,
                "error": "Bad Request - Invalid Cypher query",
                "details": response.json().get("errors", []),
                "status_code": 400
            }
        if response.status_code == 401:
            return {"success": False, "error": "Authentication failed. Check your API key.", "status_code": 401}
        return {
            "success": False,
            "error": f"Query failed with status {response.status_code}",
            "details": response.text,
            "status_code": response.status_code
        }

    def upload_saved_queries(self, queries_file: str = DEFAULT_QUERIES_FILE) -> bool:
        """
        Upload custom saved queries to BloodHound.
        If a query with the same name exists, it will be deleted and replaced.

        Args:
            queries_file: Path to queries JSON file

        Returns:
            True if all queries uploaded successfully, False otherwise
        """
        try:
            with open(queries_file, 'r') as f:
                queries = json.load(f).get("queries", [])

            if not queries:
                print(f"No queries found in {queries_file}")
                return False

            print("Uploading saved queries to BloodHound...")
            saved_queries_url = self._url("saved-queries")

            # Existing queries by name, so same-named queries can be replaced
            existing_queries = {}
            try:
                list_response = self.session.get(saved_queries_url, timeout=30)
                if list_response.status_code == 200:
                    existing_queries = {q.get("name"): q.get("id") for q in list_response.json().get("data", [])}
            except Exception as e:
                print(f"  Warning: Could not fetch existing queries: {e}")

            success_count = 0
            error_count = 0
            updated_count = 0

            for query_obj in queries:
                query_name = query_obj.get("name", "Unnamed Query")

                # The Cypher query is the first item in queryList
                query_list = query_obj.get("queryList", [])
                if not query_list:
                    print(f"  ✗ Skipped: {query_name} (no queries in queryList)")
                    error_count += 1
                    continue

                cypher_query = query_list[0].get("query", "")
                if not cypher_query:
                    print(f"  ✗ Skipped: {query_name} (empty query)")
                    error_count += 1
                    continue

                # Delete an existing query with the same name (POST anyway if this fails)
                if query_name in existing_queries:
                    delete_response = self.session.delete(
                        f"{saved_queries_url}/{existing_queries[query_name]}", timeout=30
                    )
                    if delete_response.status_code in (200, 204):
                        updated_count += 1

                response = self.session.post(
                    saved_queries_url, json={"name": query_name, "query": cypher_query}, timeout=30
                )

                if response.status_code in (200, 201):
                    print(f"  {'↻ Updated' if query_name in existing_queries else '✓ Uploaded'}: {query_name}")
                    success_count += 1
                elif response.status_code == 400 and "duplicate name" in response.text.lower():
                    # Still exists somehow, treat as warning
                    print(f"  ⚠ Already exists (could not update): {query_name}")
                    success_count += 1
                else:
                    print(f"  ✗ Failed to upload: {query_name} (status {response.status_code})")
                    print(f"    Response: {response.text}")
                    error_count += 1

            summary = f"\nQuery upload summary: {success_count} successful"
            if updated_count:
                summary += f" ({updated_count} updated)"
            if error_count:
                summary += f", {error_count} failed"
            print(summary)

            return error_count == 0

        except FileNotFoundError:
            print(f"Error: {queries_file} not found")
            return False
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {queries_file}: {e}")
            return False
        except requests.exceptions.RequestException as e:
            print(f"Error: Could not reach BloodHound at {self.base_url}: {e}")
            return False
        except Exception as e:
            print(f"Error uploading saved queries: {e}")
            return False
