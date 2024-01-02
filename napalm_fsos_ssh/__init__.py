"""napalm_fsos package."""

# Import stdlib
import pkg_resources

# Import local modules
from napalm_fsos_ssh.fsos import FsosDriver

try:
    __version__ = pkg_resources.get_distribution("napalm_fsos_ssh").version
except pkg_resources.DistributionNotFound:
    __version__ = "Not installed"

__all__ = ("FsosDriver",)
