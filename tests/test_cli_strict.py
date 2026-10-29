import json
from remote_host_inventory.cli import main

def test_duplicate_host_fails_only_when_strict(tmp_path, capsys):
    p = tmp_path / "inventory.json"
    item = {"name":"lab","host":"pi.local"}
    p.write_text(json.dumps([item,item]))
    assert main([str(p)]) == 0
    assert main(["--strict", str(p)]) == 1
    assert "duplicate_target" in capsys.readouterr().out

def test_strict_accepts_unique_hosts(tmp_path):
    p = tmp_path / "inventory.json"
    p.write_text(json.dumps([{"name":"lab","host":"pi.local"}]))
    assert main(["--strict", str(p)]) == 0
