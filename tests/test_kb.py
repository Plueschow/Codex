from pathlib import Path

from rjscan.kb import load_gadgets, match_gadgets


def test_kb_matching():
    gadgets = load_gadgets(Path(__file__).parents[1] / "kb" / "gadgets.yml")
    text = "org.apache.commons.collections InvokerTransformer"
    matches = match_gadgets(text, gadgets)
    assert matches
    assert matches[0].name == "CommonsCollections1"
