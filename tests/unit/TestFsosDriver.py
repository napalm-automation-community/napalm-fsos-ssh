import unittest

from napalm.base.test.base import TestConfigNetworkDriver

from napalm_fsos_ssh import fsos


class TestConfigROSDriver(unittest.TestCase, TestConfigNetworkDriver):
    @classmethod
    def setUpClass(cls):
        """Executed when the class is instantiated."""
        cls.vendor = "fsos"
        cls.device = fsos.FsosDriver(
            "127.0.0.1",
            "user",
            "password",
            timeout=60,
        )
        cls.device.open()
