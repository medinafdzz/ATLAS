"""Read-only metadata adapters for CI, quality gates and source control."""
import base64
import json
import re
import urllib.parse
import urllib.request

PROVIDERS = ("jenkins", "sonarqube", "bitbucket-cloud", "bitbucket-server")
MAX_BODY = 1048576

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect blocked for authenticated integration")

def build_endpoint(provider, base_url, resource):
    if provider not in PROVIDERS:
        raise ValueError("unknown provider")
    if not 1 <= len(resource) <= 256:
        raise ValueError("invalid resource")
    parts = resource.split("/")
    if not 1 <= len(parts) <= 8 or any(p in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", p) for p in parts):
        raise ValueError("invalid resource")
    base = base_url.rstrip("/")
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ("https", "http") or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("invalid URL")
    q = lambda s: urllib.parse.quote(s, safe="")
    if provider == "jenkins":
        path = "/".join("job/" + q(p) for p in parts) + "/lastCompletedBuild/api/json?tree=number,result,timestamp,url"
    elif provider == "sonarqube":
        if len(parts) != 1:
            raise ValueError("expected SonarQube project key")
        path = "api/qualitygates/project_status?projectKey=" + q(parts[0])
    elif provider == "bitbucket-cloud":
        if len(parts) != 2:
            raise ValueError("expected workspace/repository")
        path = "2.0/repositories/{}/{}/commits?pagelen=1".format(q(parts[0]), q(parts[1]))
    else:
        if len(parts) != 2:
            raise ValueError("expected project/repository")
        path = "rest/api/1.0/projects/{}/repos/{}/commits?limit=1".format(q(parts[0]), q(parts[1]))
    return base + "/" + path

def fetch_status(provider, base_url, resource, token="", username="", allow_http=False, opener=None):
    endpoint = build_endpoint(provider, base_url, resource)
    scheme = urllib.parse.urlparse(endpoint).scheme
    if scheme != "https" and not allow_http:
        raise ValueError("HTTPS required")
    if scheme == "http" and token:
        raise ValueError("refusing access token over HTTP")
    headers = {"Accept": "application/json"}
    if token:
        if provider == "jenkins":
            if not username:
                raise ValueError("Jenkins username required")
            auth = base64.b64encode((username + ":" + token).encode("utf-8")).decode("ascii")
            headers["Authorization"] = "Basic " + auth
        else:
            headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(endpoint, headers=headers, method="GET")
    sender = opener or urllib.request.build_opener(NoRedirect()).open
    with sender(request, timeout=8) as response:
        length = response.getheader("Content-Length")
        if length and int(length) > MAX_BODY:
            raise ValueError("response too large")
        content = response.read(MAX_BODY + 1)
    if len(content) > MAX_BODY:
        raise ValueError("response too large")
    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("invalid response")
    result = {"provider": provider, "resource": resource, "observed": True}
    if provider == "jenkins":
        result.update(build=data.get("number"), status=data.get("result"), observed_at=data.get("timestamp"))
    elif provider == "sonarqube":
        result.update(status=data.get("projectStatus", {}).get("status"))
    elif provider == "bitbucket-cloud":
        values = data.get("values", [])
        result.update(revision=values[0].get("hash") if values else None)
    else:
        values = data.get("values", [])
        result.update(revision=values[0].get("id") if values else None)
    return result
