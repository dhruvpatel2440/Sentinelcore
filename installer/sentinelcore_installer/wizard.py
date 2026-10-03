"""The guided setup wizard. Collects and validates; never installs anything."""

from __future__ import annotations

from typing import Callable

from . import netinfo
from . import validators as v
from .common import find_asset
from .configgen import Answers, generate_password
from .ui import UI

NEXT, BACK, CANCEL = "next", "back", "cancel"

STEP_HELP = {
    "interface": (
        "SentinelCore watches traffic on this network interface. To see other "
        "machines' traffic the interface must receive a copy of it: a switch "
        "mirror (SPAN) port, or in VirtualBox a second adapter with Promiscuous "
        "Mode set to 'Allow All'. The interface that carries your own "
        "management connection only shows traffic to and from this machine."
    ),
    "network": (
        "The network range you are allowed to monitor, in CIDR form "
        "(for example 192.168.56.0/24). Discovery scans and detections are "
        "scoped to this range."
    ),
    "protected": (
        "Addresses that can never be firewall-blocked, no matter what: your "
        "gateway, your DNS servers and this machine. Containment can therefore "
        "never cut you off. Separate entries with commas."
    ),
}

FALLBACK_EULA = (
    "SentinelCore - End User Licence Agreement\n\n"
    "SentinelCore is proprietary software. All rights reserved.\n"
    "Use it only on networks you own or are explicitly authorised to monitor.\n"
    "It is provided as is, without warranty. The full text could not be loaded "
    "from this installation; see the EULA.txt shipped with the package."
)


def load_eula() -> str:
    path = find_asset("EULA.txt")
    if path:
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            pass
    return FALLBACK_EULA


class Wizard:
    def __init__(self, ui: UI, answers: Answers | None = None, *, accept_eula: bool = False):
        self.ui = ui
        self.a = answers or Answers()
        self.accept_eula = accept_eula
        self.interfaces = netinfo.list_interfaces()
        self.gateway, self.default_iface = netinfo.default_route()
        self._edit_return = False
        self.steps: list[tuple[str, Callable[[], str]]] = [
            ("welcome", self.step_welcome),
            ("type", self.step_type),
            ("access", self.step_access),
            ("interface", self.step_interface),
            ("network", self.step_network),
            ("protected", self.step_protected),
            ("admin", self.step_admin),
            ("options", self.step_options),
            ("review", self.step_review),
        ]

    # -- driver ------------------------------------------------------------
    def run(self) -> Answers | None:
        idx = 0
        while 0 <= idx < len(self.steps):
            name, fn = self.steps[idx]
            if self._skipped(name):
                idx += 1 if self._direction >= 0 else -1  # type: ignore[attr-defined]
                continue
            result = fn()
            if result == CANCEL:
                return None
            if result == BACK:
                self._direction = -1
                idx -= 1
            elif result.startswith("goto:"):
                target = result.split(":", 1)[1]
                self._edit_return = True
                self._direction = 1
                idx = [n for n, _ in self.steps].index(target)
            else:
                self._direction = 1
                if self._edit_return and name != "review":
                    self._edit_return = False
                    idx = [n for n, _ in self.steps].index("review")
                else:
                    idx += 1
        if idx < 0:
            return None
        return self.a

    _direction = 1

    def _skipped(self, name: str) -> bool:
        if self._edit_return:
            return False
        return self.a.install_type == "quick" and name in {"access", "options"}

    # -- helpers -----------------------------------------------------------
    def _ask(self, title: str, text: str, default: str, validate: Callable[[str], object]):
        """Prompt until valid. Returns (validated value) or None for Back."""
        while True:
            raw = self.ui.input(title, text, default)
            if raw is None:
                return None
            try:
                return validate(raw)
            except v.ValidationError as exc:
                self.ui.msg("Please check that value", str(exc))
                default = raw

    def _iface(self, name: str):
        return next((i for i in self.interfaces if i.name == name), None)

    def _host_addresses(self) -> list[str]:
        return netinfo.host_addresses(self.interfaces)

    # -- screens -----------------------------------------------------------
    def step_welcome(self) -> str:
        if self.accept_eula:
            return NEXT
        self.ui.msg(
            "Welcome to SentinelCore",
            "This wizard asks a few questions, writes a configuration for this "
            "machine, then installs and starts everything automatically.\n\n"
            "Use Back at any prompt to return to the previous screen.",
        )
        ok = self.ui.scroll("Licence agreement", load_eula(), "Accept", "Decline")
        return NEXT if ok else CANCEL

    def step_type(self) -> str:
        choice = self.ui.menu(
            "Install type",
            "Quick uses safe defaults (dashboard on this machine only, HTTPS on "
            "port 443). Custom lets you choose addresses, ports and options.",
            [("quick", "Quick (recommended)"), ("custom", "Custom")],
            default=self.a.install_type,
        )
        if choice is None:
            return BACK
        self.a.install_type = choice
        return NEXT

    def step_access(self) -> str:
        addrs = self._host_addresses()
        items = [("127.0.0.1", "This computer only (localhost)")]
        items += [(ip, f"LAN: listen on {ip}") for ip in addrs]
        items.append(("0.0.0.0", "All interfaces (0.0.0.0)"))
        choice = self.ui.menu(
            "Who can open the dashboard?",
            "Localhost is the safest choice. Choose a LAN address only if other "
            "machines must reach the dashboard.",
            items, default=self.a.listen_address,
        )
        if choice is None:
            return BACK
        self.a.listen_address = choice

        while True:
            raw = self.ui.input(
                "Ports", "HTTP port (redirects to HTTPS), then HTTPS port, separated by a comma.",
                f"{self.a.http_port},{self.a.https_port}",
            )
            if raw is None:
                return BACK
            try:
                parts = [p.strip() for p in raw.split(",")]
                if len(parts) != 2:
                    raise v.ValidationError("Enter two ports separated by a comma, e.g. 80,443.")
                self.a.http_port, self.a.https_port = v.validate_port_pair(*parts)
                break
            except v.ValidationError as exc:
                self.ui.msg("Please check that value", str(exc))

        data = self._ask(
            "Data directory",
            "Where backups are stored. (Database and report volumes are managed by Docker.)",
            self.a.data_dir, v.validate_data_dir,
        )
        if data is None:
            return BACK
        self.a.data_dir = data
        return NEXT

    def step_interface(self) -> str:
        cands = netinfo.capture_candidates(self.interfaces)
        if not cands:
            self.ui.msg("No interface found", "No usable network interface was found. Attach one and run the installer again.")
            return CANCEL
        items = []
        for i in cands:
            tag = "  (management: default route)" if i.name == self.default_iface else ""
            items.append((i.name, f"{i.describe()}{tag}"))
        # Prefer an interface that is NOT the one carrying the default route.
        preferred = next((i.name for i in cands if i.name != self.default_iface), cands[0].name)
        default = self.a.capture_interface or preferred
        while True:
            choice = self.ui.menu("Capture interface", STEP_HELP["interface"], items, default=default)
            if choice is None:
                return BACK
            if choice == self.default_iface:
                ok = self.ui.yesno(
                    "This is your management interface",
                    f"{choice} carries this machine's default route. You will only see traffic "
                    "to and from this machine, not the rest of the network.\n\nUse it anyway?",
                    "Use it", "Choose another", default_yes=False,
                )
                if ok is None:
                    return BACK
                if not ok:
                    default = choice
                    continue
            iface = self._iface(choice)
            if iface and not iface.promiscuous:
                self.ui.msg(
                    "Promiscuous mode",
                    f"{choice} is not in promiscuous mode. For a mirror port or VirtualBox "
                    "'Allow All' adapter this is normal: the sensor enables capture itself. "
                    "If you see no traffic later, run: sudo sentinelcore doctor",
                )
            self.a.capture_interface = choice
            return NEXT

    def step_network(self) -> str:
        iface = self._iface(self.a.capture_interface)
        default = self.a.monitored_network or (iface.first_network() if iface else "") or ""
        value = self._ask("Monitored network", STEP_HELP["network"], default, v.validate_cidr)
        if value is None:
            return BACK
        self.a.monitored_network = value
        return NEXT

    def step_protected(self) -> str:
        detected = [ip for ip in [self.gateway, *netinfo.dns_servers()] if ip]
        default = ",".join(self.a.protected_ips or detected)
        value = self._ask("Protected IP addresses", STEP_HELP["protected"], default, v.validate_protected_ips)
        if value is None:
            return BACK
        merged = list(value)
        for own in self._host_addresses():
            if own not in merged:
                merged.append(own)
        self.a.protected_ips = merged
        self.ui.msg(
            "Protected addresses",
            "These addresses can never be blocked:\n  " + ", ".join(merged)
            + "\n\nThis machine's own addresses were added automatically.",
        )
        return NEXT

    def step_admin(self) -> str:
        user = self._ask(
            "Administrator account", "Username for the first administrator.",
            self.a.admin_username, v.validate_username,
        )
        if user is None:
            return BACK
        self.a.admin_username = user
        email = self._ask(
            "Administrator email (optional)",
            "Used for notifications and password reset. Leave blank to skip.",
            self.a.admin_email, v.validate_email,
        )
        if email is None:
            return BACK
        self.a.admin_email = email

        mode = self.ui.menu(
            "Administrator password",
            "Choose your own password (12+ characters), or let the installer generate "
            "a strong one and show it once at the end.",
            [("prompt", "I will type a password"), ("generate", "Generate a strong password for me")],
            default=self.a.admin_password_mode,
        )
        if mode is None:
            return BACK
        self.a.admin_password_mode = mode
        if mode == "generate":
            self.a.admin_password = generate_password()
            return NEXT
        while True:
            pw = self.ui.password("Administrator password", "Enter a password (at least 12 characters).")
            if pw is None:
                return BACK
            score, feedback = v.password_strength(pw, self.a.admin_username)
            try:
                v.validate_password(pw, self.a.admin_username)
            except v.ValidationError as exc:
                self.ui.msg("Password too weak", str(exc))
                continue
            again = self.ui.password("Confirm password", f"Strength: {feedback}\n\nType the password again.")
            if again is None:
                continue
            if again != pw:
                self.ui.msg("Passwords differ", "The two passwords do not match. Try again.")
                continue
            self.a.admin_password = pw
            return NEXT

    def step_options(self) -> str:
        rules = self.ui.yesno(
            "Suricata rules",
            "Download the latest Suricata detection rules after install?\n"
            "(Needs internet. You can also do this later from the dashboard.)",
            default_yes=self.a.suricata_rules_update,
        )
        if rules is None:
            return BACK
        self.a.suricata_rules_update = rules
        days = self._ask(
            "Event retention", "How many days to keep detailed events (1-3650).",
            str(self.a.event_retention_days), v.validate_retention_days,
        )
        if days is None:
            return BACK
        self.a.event_retention_days = days
        return NEXT

    def review_text(self) -> str:
        a = self.a
        pw = "(generated, shown once at the end)" if a.admin_password_mode == "generate" else "********"
        return (
            f"Dashboard         {a.dashboard_url}  (listen {a.listen_address})\n"
            f"Ports             HTTP {a.http_port}, HTTPS {a.https_port}\n"
            f"Data directory    {a.data_dir}\n"
            f"Capture interface {a.capture_interface}\n"
            f"Monitored network {a.monitored_network}\n"
            f"Protected IPs     {', '.join(a.protected_ips)}\n"
            f"Admin             {a.admin_username}  password {pw}\n"
            f"Admin email       {a.admin_email or '(none)'}\n"
            f"Update rules      {'yes' if a.suricata_rules_update else 'no'}\n"
            f"Retention         {a.event_retention_days} days\n"
        )

    def step_review(self) -> str:
        choice = self.ui.menu(
            "Review",
            self.review_text(),
            [("install", "Install now"), ("edit", "Edit a setting"), ("cancel", "Cancel")],
            default="install",
        )
        if choice is None:
            return BACK
        if choice == "cancel":
            return CANCEL
        if choice == "install":
            try:
                self.a.validate()
            except v.ValidationError as exc:
                self.ui.msg("Cannot continue", str(exc))
                return "goto:type"
            return NEXT
        target = self.ui.menu(
            "Edit which setting?", "Pick a section to change.",
            [("access", "Access, ports, data directory"), ("interface", "Capture interface"),
             ("network", "Monitored network"), ("protected", "Protected IPs"),
             ("admin", "Admin account"), ("options", "Options")],
        )
        if target is None:
            return "goto:review"
        return f"goto:{target}"
