"""ransom_payment build side: price check and chainseed template patching."""

import pytest

from software.ransom_payment import service


def test_price_must_match_contract_constant():
    assert service.contract_price_wei() == 10**18
    service.RansomPayment(price_eth=1)
    with pytest.raises(ValueError, match="RANSOM_WEI"):
        service.RansomPayment(price_eth=2)


def test_each_payment_has_its_own_deployer_key():
    a, b = service.RansomPayment(), service.RansomPayment()
    assert a._attacker_key != b._attacker_key
    assert a._attacker_key.startswith("0x") and len(a._attacker_key) == 66


def test_template_patch_fails_loudly_when_chainseed_changes():
    assert service._replace_once("a 'gas': 2000000 b", "'gas': 2000000", "X", "f") == "a X b"
    with pytest.raises(RuntimeError, match="template changed"):
        service._replace_once("no match here", "'gas': 2000000", "X", "f")


def test_client_settings_need_attach():
    with pytest.raises(ValueError, match="attachTo"):
        service.RansomPayment().clientSettings()
