"""Build time: a private chain that enforces ransom payment.

    payment = RansomPayment(price_eth=1).attachTo(emu, asn=151, attacker="attacker")

``attachTo`` adds three Geth nodes, a faucet and a chainseed utility server
that deploys RansomExchange into the given AS, plus a layer that, at render
time, (a) pins the utility's deployer account to a key generated here and
fixes the deploy gas, (b) installs the attacker watcher, and (c) resolves the
victim client settings (RPC / faucet / utility URLs) from the real network.

All chainseed code of the toolkit lives in this folder.
"""

import re
from pathlib import Path

from eth_account import Account
from seedemu.core import Binding, Filter, Layer

from software.core import install

HERE = Path(__file__).resolve().parent
CONTRACT_DIR = HERE / "contracts"
CONTRACT_NAME = "RansomExchange"
RPC_PORT = 8545
FAUCET_PORT = 80
UTILITY_PORT = 8080
UTILITY_DIR = "/utility_server"
# The contract's creation plus code deposit needs more than chainseed's pinned
# 2,000,000 gas; with too little the deploy died silently (the stock template
# never checks the receipt status).
DEPLOY_GAS = 4500000


def contract_price_wei() -> int:
    """RANSOM_WEI is a contract constant (chainseed cannot pass constructor args)."""
    source = (CONTRACT_DIR / f"{CONTRACT_NAME}.sol").read_text(encoding="utf-8")
    match = re.search(r"RANSOM_WEI\s*=\s*(\d+)\s*ether", source)
    if not match:
        raise ValueError("could not read RANSOM_WEI from the contract source")
    return int(match.group(1)) * 10**18


class RansomPayment:
    def __init__(self, price_eth: int = 1, chain_id: int = 18000, chain_name: str = "RansomLab",
                 fund_max: int = 5, auto_reply: bool = True, node_prefix: str = ""):
        price_wei = int(price_eth * 10**18)
        if price_wei != contract_price_wei():
            raise ValueError(
                f"price_eth={price_eth} but RansomExchange.sol fixes RANSOM_WEI at "
                f"{contract_price_wei() // 10**18} ether; edit the contract and rerun "
                "contracts/compile_contract.py to change the price"
            )
        self.price_wei = price_wei
        self.chain_id = chain_id
        self.chain_name = chain_name
        self.fund_max = fund_max
        self.auto_reply = auto_reply
        self.prefix = node_prefix
        attacker = Account.create()
        key = attacker.key.hex()
        self._attacker_key = key if key.startswith("0x") else "0x" + key
        self._attacker_address = attacker.address
        self._attacker = None
        self._release = None  # (package, argv)
        self._nodes = {}
        self._attached = False

    # ---- topology -----------------------------------------------------------
    def _name(self, role: str) -> str:
        return f"{self.prefix}{role}"

    def attachTo(self, emu, asn: int, network: str = "net0", attacker=None):
        from chainseed.services.ethereum import ConsensusMechanism, EthereumService

        if self._attached:
            raise ValueError("this RansomPayment is already attached")
        lab_as = emu.getLayer("Base").getAutonomousSystem(asn)
        ethereum = EthereumService()
        chain = ethereum.createBlockchain(chainName=self.chain_name,
                                          consensus=ConsensusMechanism.POA)
        chain.setChainId(self.chain_id)
        for index in range(3):
            name = self._name(f"chain{index}")
            self._nodes[f"chain{index}"] = lab_as.createHost(name).joinNetwork(network)
            node = chain.createNode(name)
            node.enableGethHttp()
            node.unlockAccounts()
            if index < 2:
                node.startMiner()
            if index == 0:
                node.setBootNode(True)
            emu.addBinding(Binding(name, filter=Filter(asn=asn, nodeName=name)))

        faucet = self._name("faucet")
        self._nodes["faucet"] = lab_as.createHost(faucet).joinNetwork(network)
        chain.createFaucetServer(vnode=faucet, port=FAUCET_PORT,
                                 linked_eth_node=self._name("chain2"),
                                 balance=10000, max_fund_amount=10)
        emu.addBinding(Binding(faucet, filter=Filter(asn=asn, nodeName=faucet)))

        utility = self._name("utility")
        self._nodes["utility"] = lab_as.createHost(utility).joinNetwork(network)
        server = chain.createEthUtilityServer(vnode=utility, port=UTILITY_PORT,
                                              linked_eth_node=self._name("chain2"),
                                              linked_faucet_node=faucet)
        server.deployContractByContent(
            CONTRACT_NAME,
            (CONTRACT_DIR / f"{CONTRACT_NAME}.abi").read_text(encoding="utf-8"),
            (CONTRACT_DIR / f"{CONTRACT_NAME}.bin").read_text(encoding="utf-8"),
        )
        emu.addBinding(Binding(utility, filter=Filter(asn=asn, nodeName=utility)))

        emu.addLayer(ethereum)
        emu.addLayer(_PaymentLayer(self))
        self._attached = True
        if attacker is not None:
            self.setAttacker(attacker)
        return self

    def setAttacker(self, node):
        """The host (node object or vnode name) where the watcher runs."""
        self._attacker = node
        return self

    def setReleaseTool(self, package, argv):
        """Contract 3, attacker side: the payload's own key-release command.

        ``package`` is a PayloadPackage installed next to the watcher; ``argv``
        reads the on-chain blob on stdin and prints the reply.
        """
        self._release = (package, list(argv))
        return self

    def nodes(self) -> dict:
        return dict(self._nodes)

    # ---- settings -------------------------------------------------------------
    def clientSettings(self, emulator=None) -> dict:
        """Victim client settings, resolved from the real addresses."""
        if not self._attached:
            raise ValueError("call attachTo(emu, asn) before installing payment clients")
        ip = {role: install.node_ip(node) for role, node in self._nodes.items()}
        return {
            "chain_id": self.chain_id,
            "rpc_url": f"http://{ip['chain2']}:{RPC_PORT}",
            "faucet_url": f"http://{ip['faucet']}:{FAUCET_PORT}/fundme",
            "utility_url": f"http://{ip['utility']}:{UTILITY_PORT}",
            "contract_name": CONTRACT_NAME,
            "ransom_wei": self.price_wei,
            "fund_max": self.fund_max,
        }

    def clientPackage(self):
        """What a payload merges in to talk to this payment (contract 3)."""
        return install.package("ransom_payment_client", ["ransom_payment"],
                               settings={"ransom_payment": self.clientSettings})

    def watcherSettings(self, emulator=None) -> dict:
        cfg = self.clientSettings(emulator)
        cfg.update({
            "attacker_private_key": self._attacker_key,
            "attacker_address": self._attacker_address,
            "release_argv": self._release[1] if self._release else [],
            "poll_seconds": 5,
        })
        return cfg

    def watcherPackage(self):
        return install.package(
            "ransom_watcher", ["ransom_payment"],
            settings={"ransom_watcher": self.watcherSettings},
            launchers={"yom-ransom-watcher": "software.ransom_payment.runtime.watcher"},
            start="yom-ransom-watcher run" if self.auto_reply else None,
        )


class _PaymentLayer(Layer):
    """Render-time half of RansomPayment (after chainseed has rendered)."""

    def __init__(self, payment: RansomPayment):
        super().__init__()
        self.payment = payment
        self.addDependency("EthereumService", False, False)
        self.addDependency("Base", False, False)

    def getName(self) -> str:
        return "RansomPayment"

    def render(self, emulator):
        p = self.payment
        self._fix_utility(p._nodes["utility"])
        if p._attacker is not None:
            node = install.resolve_node(emulator, p._attacker)
            if p._release:
                install.install_package(emulator, node, p._release[0])
            install.install_package(emulator, node, p.watcherPackage())
            self._log(f"watcher installed on as{node.getAsn()}/{node.getName()}")

    def _fix_utility(self, node):
        p = self.payment
        fund_path = f"{UTILITY_DIR}/fund_account.py"
        deploy_path = f"{UTILITY_DIR}/deploy_contract.py"
        fund = _content(node, fund_path)
        deploy = _content(node, deploy_path)

        old_call = "    account_address, private_key = createAccount()\n"
        new_call = (
            "    # RansomPayment: the deployer (= the contract's attacker) is a key\n"
            "    # generated at build time, so the attacker watcher can hold it too.\n"
            "    account_address, private_key = readAccountFromJson()\n"
        )
        reader = (
            "\ndef readAccountFromJson():\n"
            "    with open(DIR_PREFIX + '/account.json') as file:\n"
            "        acct = json.load(file)\n"
            "    return acct['address'], acct['private_key']\n\n"
        )
        fund = _replace_once(fund, old_call, new_call, fund_path)
        fund = _replace_once(fund, "\ndef createAccount():", reader + "def createAccount():", fund_path)

        deploy = _replace_once(deploy, "'gas': 2000000", f"'gas': {DEPLOY_GAS}", deploy_path)
        receipt = "    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)\n"
        deploy = _replace_once(
            deploy, receipt,
            receipt
            + "    if tx_receipt.status != 1:\n"
            + "        logging.error(f'deployment of {contract_name} REVERTED: {tx_hash.hex()}')\n"
            + "        raise SystemExit(1)\n",
            deploy_path,
        )
        node.setFile(fund_path, fund)
        node.setFile(deploy_path, deploy)
        node.setFile(f"{UTILITY_DIR}/account.json",
                     '{"address": "%s", "private_key": "%s"}\n'
                     % (p._attacker_address, p._attacker_key))


def _content(node, path: str) -> str:
    for f in node.getFiles():
        file_path, content = f.get()
        if file_path == path:
            return content
    raise RuntimeError(f"chainseed did not generate {path}; is this chainseed 0.1.0a0?")


def _replace_once(text: str, old: str, new: str, where: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(f"chainseed template changed: cannot patch {where!r} ({old.strip()!r})")
    return text.replace(old, new)
