"""Ransomware: the installer (build time).

    ransom = Ransomware(in_as=lab, on_network="net0")   brings its payment chain
    emu.addLayer(ransom)
    for binding in ransom.bindings:
        emu.addBinding(binding)

    worm = Worm(entry=bof.exploit(), payload=ransom.payload, ...)
    emu.addLayer(worm)

What this puts into the emulation:

  - the payment chain: three chain nodes, a faucet and a utility server that
    deploys the RansomExchange contract, all on the network the case names.
    This is the original v2 chain setup, with one manual step removed: the
    attacker used to copy the utility server's account key over by hand. Now
    the installer creates that account when the lab is built and hands it to
    both the utility server and the attacker.
  - the ransomware itself is put nowhere in advance: it is what the worm
    carries. The Worm installer puts the attacker's tools on the machine the
    worm is launched from (see RansomwarePayload.stage).

It is a chain-seed EthereumService, so the chain is installed by chain-seed
and compiled with chain-seed's compiler (ChainSeedDocker).
"""

import json
from pathlib import Path

from chainseed.services.ethereum import ConsensusMechanism, EthereumService
from eth_account import Account
from seedemu.core import Action, Binding, Filter

from software.Ransomware_Service.yom_ransomware import RansomwarePayload
from software.Ransomware_Service.yom_ransomware.payload import DOCUMENTS

HERE = Path(__file__).resolve().parent
CONTRACTS = HERE / "contracts"

CONTRACT_NAME = "RansomExchange"
#: Names of the chain's machines; each is also the virtual node bound to it.
CHAIN_NODE = "ransom-chain-{}"          # 0, 1, 2
RPC_NODE = CHAIN_NODE.format(2)         # the node victims and the attacker talk to
FAUCET = "ransom-faucet"
UTILITY = "ransom-utility"
UTILITY_PORT = 8080
RPC_PORT = 8545

#: What chain-seed's utility server runs to create its account. Its own
#: version makes a new random account on every boot; this one reuses an
#: account placed there when the lab was built.
_REUSE_ACCOUNT = """\
def reuseOrCreateAccount():
    # Reuse a key placed here when the lab was built, so that the attacker can
    # hold the very account the contract will call its attacker.
    path = DIR_PREFIX + '/account.json'
    if __import__('os').path.exists(path):
        with open(path) as handle:
            saved = json.load(handle)
        return saved['address'], saved['private_key']
    return createAccount()

"""


def _adjust_chainseed_templates():
    """Two small corrections to chain-seed's utility server scripts.

    - The contract needs more deployment gas than chain-seed's pinned
      2,000,000; without it the deployment dies silently (as in v2).
    - Reuse an account that is already there instead of making a new one.
    """
    from chainseed.services.ethereum.EthTemplates import UtilityServerFileTemplates

    deploy = UtilityServerFileTemplates["deploy_contract"]
    if "'gas': 2000000" in deploy:
        UtilityServerFileTemplates["deploy_contract"] = deploy.replace(
            "'gas': 2000000", "'gas': 4500000"
        )
    fund = UtilityServerFileTemplates["fund_account"]
    if "reuseOrCreateAccount" not in fund:
        changed = fund.replace("def createAccount():", _REUSE_ACCOUNT + "def createAccount():")
        changed = changed.replace(
            "account_address, private_key = createAccount()",
            "account_address, private_key = reuseOrCreateAccount()",
        )
        if ("def reuseOrCreateAccount():" not in changed
                or "= reuseOrCreateAccount()" not in changed):
            raise RuntimeError(
                "chain-seed's fund_account.py changed; the account reuse patch no longer fits"
            )
        UtilityServerFileTemplates["fund_account"] = changed


_adjust_chainseed_templates()


def new_chain_account() -> dict:
    """A fresh account for the lab: the one that deploys the ransom contract."""
    account = Account.create()
    key = getattr(account, "key", None)
    if key is None:
        key = account.privateKey
    return {"address": account.address, "private_key": key.hex()}


class Ransomware(EthereumService):
    """The ransomware as a seedemu service: its payment chain, and the payload."""

    def __init__(self, in_as, on_network: str = "net0", chain_id: int = 18000,
                 documents: str = DOCUMENTS, ransom_wei: int = 10**18):
        super().__init__()
        self.payload = RansomwarePayload(documents=documents)
        self._chain_id = chain_id
        self._ransom_wei = ransom_wei
        # The contract's deployer is its "attacker". Both the utility server
        # and the attacker's machine get this key; it is never shipped in the
        # worm body.
        self._chain_key = new_chain_account()

        asn = in_as.getAsn()
        self.bindings = []
        chain = self.createBlockchain(chainName="RansomLab", consensus=ConsensusMechanism.POA)
        chain.setChainId(chain_id)

        def machine(name):
            in_as.createHost(name).joinNetwork(on_network)
            self.bindings.append(Binding(name, Action.FIRST, Filter(asn=asn, nodeName=name)))

        for index in range(3):
            name = CHAIN_NODE.format(index)
            machine(name)
            node = chain.createNode(name)
            node.enableGethHttp()
            node.unlockAccounts()
            if index < 2:
                node.startMiner()
            if index == 0:
                node.setBootNode(True)

        machine(FAUCET)
        chain.createFaucetServer(vnode=FAUCET, port=80, linked_eth_node=RPC_NODE,
                                 balance=10000, max_fund_amount=10)

        machine(UTILITY)
        utility = chain.createEthUtilityServer(vnode=UTILITY, port=UTILITY_PORT,
                                               linked_eth_node=RPC_NODE, linked_faucet_node=FAUCET)
        utility.deployContractByContent(
            CONTRACT_NAME,
            (CONTRACTS / (CONTRACT_NAME + ".abi")).read_text(encoding="utf-8"),
            (CONTRACTS / (CONTRACT_NAME + ".bytecode")).read_text(encoding="utf-8"),
        )

    def getName(self) -> str:
        return "Ransomware"

    def render(self, emulator):
        super().render(emulator)            # the chain, the faucet, the utility server

        def address(vnode):
            return str(emulator.getBindingFor(vnode).getInterfaces()[0].getAddress())

        self.payload.chain = {
            "chain_id": self._chain_id,
            "rpc_url": "http://{}:{}".format(address(RPC_NODE), RPC_PORT),
            "faucet_url": "http://{}/fundme".format(address(FAUCET)),
            "utility_url": "http://{}:{}".format(address(UTILITY), UTILITY_PORT),
            "contract_name": CONTRACT_NAME,
            "ransom_wei": self._ransom_wei,
        }
        self.payload.chain_key = self._chain_key
        emulator.getBindingFor(UTILITY).setFile(
            "/utility_server/account.json", json.dumps(self._chain_key, indent=2) + "\n"
        )
        print("Ransomware: payment chain {} at {} (faucet {}, utility {}). The attacker's "
              "account is {}".format(self._chain_id, self.payload.chain["rpc_url"],
                                     self.payload.chain["faucet_url"],
                                     self.payload.chain["utility_url"],
                                     self._chain_key["address"]))
