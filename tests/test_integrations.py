import io
import json
import pytest
from atlas.integrations import build_endpoint, fetch_status

class Response(io.BytesIO):
    def getheader(self, key):
        return None

@pytest.mark.parametrize("provider,resource,payload,key,value", [
    ("jenkins", "pipeline-a", {"number":42,"result":"SUCCESS"}, "status", "SUCCESS"),
    ("sonarqube", "sample", {"projectStatus":{"status":"OK"}}, "status", "OK"),
    ("bitbucket-cloud", "team/repo", {"values":[{"hash":"abcdef"}]}, "revision", "abcdef"),
    ("bitbucket-server", "TEAM/repo", {"values":[{"id":"a1b2c3"}]}, "revision", "a1b2c3"),
])
def test_integrations_are_get_only(provider,resource,payload,key,value):
    def opener(request, timeout):
        assert request.get_method() == "GET"
        assert request.full_url.startswith("https://example.org/")
        return Response(json.dumps(payload).encode("utf-8"))
    assert fetch_status(provider, "https://example.org", resource, opener=opener)[key] == value

def test_disallow_tokens_on_http_and_path_traversal():
    with pytest.raises(ValueError):
        fetch_status("jenkins", "http://server.local", "job")
    with pytest.raises(ValueError):
        fetch_status("jenkins", "http://server.local", "job", token="secret", username="user", allow_http=True)
    with pytest.raises(ValueError):
        build_endpoint("jenkins", "https://example.org", "x/../../etc")
