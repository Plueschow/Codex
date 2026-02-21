from pathlib import Path

from rjscan.kb import load_chains, load_gadgets, match_chains, match_gadgets


def test_chain_matching():
    base = Path(__file__).parents[1]
    gadgets = load_gadgets(base / "kb" / "gadgets.yml")
    chains = load_chains(base / "kb" / "chains.yml")
    text = "org.apache.commons.collections InvokerTransformer"
    gadget_matches = match_gadgets(text, gadgets)
    chain_matches = match_chains(gadget_matches, chains)
    assert chain_matches
    assert chain_matches[0].name == "CommonsCollections-RCE"
