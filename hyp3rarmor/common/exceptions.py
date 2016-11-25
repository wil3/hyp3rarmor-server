class Hyp3rArmorError(Exception):
    """An error occured"""

class Hyp3rArmorConfigurationError(Hyp3rArmorError):
    """An error occured with the configuration"""

class Hyp3rArmorCaptureError(Hyp3rArmorError):
    """An error occured when capturing network packets"""

class Hyp3rArmorFirewallError(Hyp3rArmorError):
    """An error occurs when modifying the firewall"""

class Hyp3rArmorGenerationError(Hyp3rArmorError):
    """An error occurs when generating a token"""

class Hyp3rArmorTokenError(Hyp3rArmorError):
    """An error occurs when generating a token"""
