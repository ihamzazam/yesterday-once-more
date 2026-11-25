"""Build time: install the deliberately vulnerable server, publish its profile.

    vuln = VulnerableServer(port=9090)
    for victim in victims:
        vuln.install(victim)
    safe = VulnerableServer(port=9090, patched=True); safe.install("safe")

    profile = vuln.profile()            # measured, never hand-typed (contract 1)
    worm.setExploit(vuln.exploit())     # the worm's entry plug, from the profile

The server's binaries live in the prebuilt ``yom-vuln:1`` image (compiled once
by ``images/build.sh vuln``); its nodes run on that image. The profile is
measured by running the image's own ``probe.py`` in a throwaway container with
the same no-ASLR personality the emulation gives its nodes; two runs must
agree or the build fails. The exploit handed to the worm carries only
measured values (contract 1), so a mismatch cannot pass silently.
"""

import json
import subprocess

from seedemu.core import Server, Service

from software.core import install

IMAGE = "yom-vuln:1"
IMAGE_BIN = "/opt/yom/vulnerable_server/bin"
IMAGE_PROBE = "/opt/yom/vulnerable_server/probe.py"

#: seedemu's compose template runs every node privileged, so the emulation
#: containers may call personality(ADDR_NO_RANDOMIZE). Plain `docker run` may
#: not (the default seccomp profile blocks it), hence the flag here.
MEASURE_DOCKER_ARGS = ("--rm", "--security-opt", "seccomp=unconfined")

PROFILE_FORMAT = "yom-profile/1"


def _measure() -> dict:
    """The measured profile, straight out of the image that victims run."""
    result = subprocess.run(
        ["docker", "run", *MEASURE_DOCKER_ARGS, IMAGE,
         "python3", IMAGE_PROBE, IMAGE_BIN, "-"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"could not measure the vulnerable server's profile from {IMAGE}.\n"
            f"Is the image built? Run: images/build.sh vuln\n\n{result.stderr}"
        )
    profile = json.loads(result.stdout)
    _check_profile(profile)
    return profile


def _check_profile(profile: dict):
    if profile.get("format") != PROFILE_FORMAT:
        raise ValueError(f"not a {PROFILE_FORMAT} profile: {profile.get('format')!r}")
    if profile.get("kind") != "stack_overflow":
        raise ValueError(f"unknown vulnerability kind: {profile.get('kind')!r}")
    measured = profile.get("measured", {})
    badfile = profile.get("badfile", {})
    for key in ("ebp", "buf"):
        if not isinstance(measured.get(key), int):
            raise ValueError(f"profile is missing a measured {key}")
    for key in ("size", "ret_offset", "ret_target"):
        if not isinstance(badfile.get(key), int):
            raise ValueError(f"profile is missing badfile.{key}")


class StackOverflow:
    """Contract 1, the exploit handed to the worm: declares what it targets.

    Plain data plus the measured values; the worm's runtime entry plug builds
    the badfile from ``settings()`` and refuses to run against anything else.
    """

    kind = "stack_overflow"

    def __init__(self, profile: dict, port: int):
        _check_profile(profile)
        if profile.get("protections", {}).get("canary"):
            raise ValueError("a canary-protected build cannot be overflowed")
        self.profile = profile
        self.port = int(port)
        self.ebp = profile["measured"]["ebp"]
        self.buf = profile["measured"]["buf"]

    def settings(self) -> dict:
        """Everything the worm's entry plug needs, as plain data."""
        return {
            "kind": self.kind,
            "port": self.port,
            "badfile": self.profile["badfile"],
            "command_room": self.profile["command_room"],
        }


class VulnerableServer:
    def __init__(self, port: int = 9090, patched: bool = False, profile: dict = None):
        """``patched=True`` installs the protected binary: teaching variant.

        ``profile`` is normally measured from the image; tests inject one.
        """
        if not (1 <= int(port) <= 65535):
            raise ValueError(f"not a port: {port}")
        self.port = int(port)
        self.patched = bool(patched)
        self._profile = profile
        self._service = None

    # ---- the published profile (contract 1) ---------------------------------
    def profile(self) -> dict:
        if self._profile is None:
            self._profile = _measure()
        return self._profile

    def exploit(self) -> StackOverflow:
        """The entry the worm will use against this server (contract 1)."""
        if self.patched:
            raise ValueError("a patched server has no exploit; that is the point")
        return StackOverflow(self.profile(), port=self.port)

    # ---- what a node runs ----------------------------------------------------
    def startCommand(self) -> str:
        start = f"cd {IMAGE_BIN}"
        if self.patched:
            start += " && cp -f stack-patched stack"
        start += f" && exec setarch i386 -R ./server {self.port}"
        return start

    def settings(self, emulator=None) -> dict:
        return {"port": self.port, "patched": self.patched,
                "image": IMAGE, "profile": self.profile()}

    def package(self):
        """Settings + the start command; the binaries come from the image."""
        return install.package("vulnerable_server", ["vulnerable_server"],
                               settings={"vulnerable_server": self.settings},
                               start=self.startCommand(),
                               needs=["cmd:setarch"])

    # ---- install (build time) ------------------------------------------------
    def install(self, vnode: str):
        """Install this server on a vnode through the seedemu Service below."""
        if self._service is None:
            self._service = VulnerableServerService(self)
        return self._service.install(vnode)

    def service(self):
        """The seedemu layer to add with ``emu.addLayer(...)``."""
        if self._service is None:
            self._service = VulnerableServerService(self)
        return self._service


class VulnerableServerServer(Server):
    def __init__(self, builder: VulnerableServer):
        super().__init__()
        self.builder = builder
        self.emulator = None

    def install(self, node):
        install.mark_image(node, IMAGE)      # the binaries live in yom-vuln:1
        install.install_package(self.emulator, node, self.builder.package())


class VulnerableServerService(Service):
    def __init__(self, builder: VulnerableServer):
        super().__init__()
        self.builder = builder
        self.addDependency("Base", False, False)

    def getName(self) -> str:
        return "VulnerableServer"

    def _createServer(self) -> Server:
        return VulnerableServerServer(self.builder)

    def render(self, emulator):
        for server, _ in self.getTargets():
            server.emulator = emulator
        super().render(emulator)
