from rjscan.graph import Endpoint, bfs_graph


def test_bfs_graph_dedupe_and_depth():
    seed = Endpoint(host="10.0.0.1", port=1099, kind="rmi_registry")
    hint_provider = {
        seed.endpoint_id: [
            ("10.0.0.2", 2000, []),
            ("10.0.0.3", 3000, []),
        ],
    }
    endpoints, edges = bfs_graph([seed], hint_provider, max_depth=1)
    assert len(endpoints) == 3
    assert len(edges) == 2
