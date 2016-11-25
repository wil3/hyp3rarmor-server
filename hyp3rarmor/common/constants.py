import os
_current_dir = os.path.abspath(os.path.dirname(__file__))
HYP3RARMOR_ROOT = os.path.normpath(os.path.join(_current_dir, "..", ".."))
HYP3RARMOR_GEN_DIR = os.path.join(HYP3RARMOR_ROOT, "gen")
SCOPE_UNIVERSAL = "universal"
SCOPE_IP = "ip"
DEFENSE_IP = "ip"
DEFENSE_DN = "dn"
MAX_PORT_NUMBER = 65535
TOTP_LENGTH = 8
