import pytest
from remote_host_inventory.core import check_inventory

def test_valid_inventory():
    out = check_inventory([{"name":"lab","host":"pi.local","port":22}])
    assert out["valid"] == 1 and not out["issues"]

def test_duplicate_targets():
    row = {"name":"lab","host":"pi.local"}
    out = check_inventory([row, row])
    assert out["valid"] == 1
    assert out["issues"][0]["code"] == "duplicate_target"

def test_reject_credential_fields():
    out = check_inventory([{"name":"pi","host":"pi.local","password":"unsafe"}])
    assert out["valid"] == 0
    assert out["issues"][0]["code"] == "credential_field"

def test_reject_missing_or_bad_host():
    out = check_inventory([{"name":"lab","host":"bad..host"},{"name":"lab"}])
    assert len(out["issues"]) == 2 and out["valid"] == 0

def test_reject_invalid_port():
    out = check_inventory([{"name":"lab","host":"pi.local","port":70000}])
    assert out["issues"][0]["code"] == "invalid_target"

def test_ipv6_target():
    out = check_inventory([{"name":"lab","host":"2001:db8::1"}])
    assert out["valid"] == 1

def test_reject_non_list():
    with pytest.raises(ValueError):
        check_inventory({"host":"pi.local"})
