from __future__ import annotations


def test_proctree_shape(server_up, base_url, http):
    r = http.get(f"{base_url}/api/proctree")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)

    def check_node(n):
        assert isinstance(n, dict)
        assert "pid" in n and "name" in n
        assert isinstance(n["pid"], int)
        assert isinstance(n["name"], str)
        children = n.get("children", [])
        if children:
            assert isinstance(children, list)
            for c in children:
                check_node(c)

    if data:
        check_node(data[0])
