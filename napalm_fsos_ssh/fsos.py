"""
Napalm driver for Skeleton.
Read https://napalm.readthedocs.io for more information.
"""

import os
import re
import socket
from ipaddress import IPv4Address, IPv4Network, ip_address

from napalm.base import NetworkDriver
from napalm.base.exceptions import ConnectionClosedException
from napalm.base.netmiko_helpers import netmiko_args

templates = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "utils/textfsm_templates/"
)
os.environ["NET_TEXTFSM"] = templates


class FsosDriver(NetworkDriver):
    platform = "fsos"

    """Napalm driver for FSOS"""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.device = None
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.vendor = "Fiberstore"
        self.device_type = "generic"

        if optional_args is None:
            optional_args = {}

        self.netmiko_optional_args = netmiko_args(optional_args)
        self.netmiko_optional_args.setdefault("port", 22)

    def open(self):
        """Implement the NAPALM method open (mandatory)"""
        self.device = self._netmiko_open(
            self.device_type, netmiko_optional_args=self.netmiko_optional_args
        )

    def close(self):
        """Implement the NAPALM method close (mandatory)"""
        self._netmiko_close()

    def _send_command(self, command, use_textfsm=False):
        """Wrapper for self.device.send.command().
        If command is a list will iterate through commands until valid command.
        """
        try:
            output = ""
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd, use_textfsm=use_textfsm)
                    output = self._send_command_postprocess(output)
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command, use_textfsm=use_textfsm)
                output = self._send_command_postprocess(output)

            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    @staticmethod
    def _send_command_postprocess(output):
        if not isinstance(output, list):
            output = output.strip()
        return output

    @staticmethod
    def _get_ip_version(ip):
        return "ip" if type(ip_address(ip)) is IPv4Address else "ipv6"

    @staticmethod
    def _format_interface_name(interface):
        if re.search(r"\d+", interface):
            interface_type = re.match(r"[A-Za-z]+", interface).group(0)
            interface_unit = (
                re.search(r"\d+(\/)?(\s+)?(\d+)?", interface).group(0).replace(" ", "")
            )
            interface = f"{interface_type.capitalize()} {interface_unit}"

        return interface

    @staticmethod
    def _format_uptime(uptime):
        uptime_sec = 0

        uptime_info = uptime.replace("and", "").replace(" ", "").split(",")

        for info in uptime_info:
            unit = re.search(r"[a-zA-Z]+", info).group(0)
            time_value = float(re.search(r"\d+(\.\d+)?", info).group(0))
            if unit == "days":
                uptime_sec += time_value * 86400
            elif unit == "hours":
                uptime_sec += time_value * 3600
            elif unit == "minutes":
                uptime_sec += time_value * 60
            elif unit == "seconds":
                uptime_sec += time_value

        return float(uptime_sec)

    @staticmethod
    def _format_speed(speed):
        if "g" in speed:
            speed_match = re.match(r"\d+", speed).group(0)
            v = f"{speed_match}000"
        else:
            v = re.match(r"\d+", speed).group(0)
        return float(v)

    @staticmethod
    def _get_protocol(protocol):
        protocols = {
            "C": "CONNECTED",
            "S": "STATIC",
            "R": "RIP",
            "B": "BGP",
            "O": "OSPF",
            "IA": "OSPF",
            "N1": "OSPF",
            "N2": "OSPF",
            "E1": "OSPF",
            "E2": "OSPF",
            "i": "ISIS",
            "L1": "ISIS",
            "L2": "ISIS",
            "ia": "ISIS",
        }

        return protocols[protocol]

    @staticmethod
    def _get_ipv6_neighbors_state(state):
        states = {
            "I1": "INCOMPLETE",
            "I2": "INVALID",
            "R": "REACHABLE",
            "S": "STALE",
            "D": "DELAY",
            "P1": "PROBE",
            "P2": "PERMANENT",
            "U": "UNKNOWN",
        }

        return states[state]

    @staticmethod
    def _sanitize_config(config):
        match_to_sanitize = [
            r"username\s+\S+\s+password.*\n",
            r"enable\s+password.*\n",
            r"snmp-server\s+usm-user.*\n.*\n",
            r"snmp-server community.*\n",
        ]
        config = re.sub("|".join(match_to_sanitize), "", config)

        return config

    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.
        Example input:
        ["show clock", "show calendar"]
        Output example:
        {   "show calendar": u"22:02:01 UTC Thu Feb 18 2016",
            "show clock": u"*22:01:51.165 UTC Thu Feb 18 2016"}
        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self._send_command(command)
            if "Incorrect usage" in output:
                raise ValueError(f"Unable to execute command {command}")
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def get_config(self, retrieve="all", full=False, sanitized=False):
        data = {
            "startup": "",
            "running": "",
            "candidate": "",
        }

        if retrieve in ["all", "running"]:
            command = "show running-config"
            config = self._send_command(command)

            if sanitized:
                config = self._sanitize_config(config)

            data["running"] = config
        if retrieve in ["all", "startup"]:
            command = "show startup-config"
            config = self._send_command(command)

            if sanitized:
                config = self._sanitize_config(config)

            data["startup"] = config

        return data

    def get_arp_table(self, vrf=""):
        command = "show arp"
        output = self._send_command(command, use_textfsm=True)

        data = []

        for entry in output:
            data.append(
                {
                    "interface": self._format_interface_name(entry["interface"]),
                    "mac": entry["mac"],
                    "ip": entry["address"],
                    "age": -1.0,
                }
            )

        return data

    def get_environment(self):
        commands = ["show system", "show memory"]
        output = {}
        for command in commands:
            output[command] = self._send_command(command, use_textfsm=True)[0]

        data = {"fans": {}, "temperature": {}, "power": {}, "cpu": {}, "memory": {}}

        for i in range(0, len(output["show system"]["system_temp_unit"])):
            data["temperature"][output["show system"]["system_temp_unit"][i]] = {
                "temperature": float(output["show system"]["system_temp_value"][i]),
                "is_alert": False,
                "is_critical": False,
            }

        for i in range(0, len(output["show system"]["system_power_unit"])):
            data["power"][output["show system"]["system_power_unit"][i]] = {
                "status": output["show system"]["system_power_value"][i] == "Up",
                "capacity": -1.0,
                "output": -1.0,
            }

        data["memory"] = {
            "available_ram": int(output["show memory"]["mem_total"])
            - int(output["show memory"]["mem_used"]),
            "used_ram": int(output["show memory"]["mem_used"]),
        }

        return data

    def get_facts(self):
        commands = ["show system", "show version", "show interfaces brief"]
        output = {}
        for command in commands:
            output[command] = self._send_command(command, use_textfsm=True)

        data = {
            "uptime": self._format_uptime(output["show system"][0]["uptime"]),
            "vendor": self.vendor,
            "os_version": output["show version"][0]["os_version"],
            "serial_number": output["show version"][0]["serial_number"],
            "model": "",
            "hostname": output["show system"][0]["hostname"],
            "fqdn": "",
            "interface_list": [
                self._format_interface_name(entry["interface"])
                for entry in output["show interfaces brief"]
            ],
        }

        return data

    def get_interfaces(self):
        command = "show interfaces brief"
        output = self._send_command(command, use_textfsm=True)

        data = {}

        for entry in output:
            data[self._format_interface_name(entry["interface"])] = {
                "is_enabled": entry["is_enabled"] in ["Up", ""],
                "is_up": entry["is_up"] == "Up",
                "description": "",
                "last_flapped": -1.0,
                "speed": self._format_speed(entry["speed"])
                if not entry["speed"] == ""
                else -1,
                "mtu": -1,
                "mac_address": "",
            }

        return data

    def get_interfaces_counters(self):
        command = "show interfaces counters"
        output = self._send_command(command, use_textfsm=True)

        data = {}

        for entry in output:
            data[self._format_interface_name(entry["interface"])] = {
                "tx_errors": -1,
                "rx_errors": -1,
                "tx_discards": int(entry["tx_discards"]),
                "rx_discards": int(entry["rx_discards"]),
                "tx_octets": int(entry["tx_octets"]),
                "rx_octets": int(entry["rx_octets"]),
                "tx_unicast_packets": int(entry["tx_unicast_packets"]),
                "rx_unicast_packets": int(entry["rx_unicast_packets"]),
                "tx_multicast_packets": int(entry["tx_multicast_packets"]),
                "rx_multicast_packets": int(entry["rx_multicast_packets"]),
                "tx_broadcast_packets": int(entry["tx_broadcast_packets"]),
                "rx_broadcast_packets": int(entry["rx_broadcast_packets"]),
            }

        return data

    def get_interfaces_ip(self):
        commands = ["show ip interface brief", "show ipv6 interface brief"]
        output = {}
        for command in commands:
            output[command] = self._send_command(command, use_textfsm=True)

        data = {}

        for entry in output["show ip interface brief"]:
            intf = self._format_interface_name(entry["interface"])
            if intf not in data:
                data[intf] = {}
            if "ipv4" not in data[intf]:
                data[intf]["ipv4"] = {}
            if entry["ip"] not in data[intf]["ipv4"]:
                data[intf]["ipv4"][entry["ip"]] = {}
            data[intf]["ipv4"][entry["ip"]]["prefix_length"] = IPv4Network(
                f"0.0.0.0/{entry['netmask']}"
            ).prefixlen

        for entry in output["show ipv6 interface brief"]:
            intf = self._format_interface_name(entry["interface"])
            if intf not in data:
                data[intf] = {}
            if "ipv6" not in data[intf]:
                data[intf]["ipv6"] = {}
            if entry["ip"] not in data[intf]["ipv6"]:
                data[intf]["ipv6"][entry["ip"]] = {}
            data[intf]["ipv6"][entry["ip"]]["prefix_length"] = int(entry["netmask"])

        return data

    def get_ipv6_neighbors_table(self):
        command = "show ipv6 neighbors"
        output = self._send_command(command, use_textfsm=True)

        data = []

        for entry in output:
            data.append(
                {
                    "interface": self._format_interface_name(entry["interface"]),
                    "mac": entry["mac"],
                    "ip": entry["ip"],
                    "age": float(entry["age"]),
                    "state": self._get_ipv6_neighbors_state(entry["state"]),
                }
            )

        return data

    def get_lldp_neighbors(self):
        command = "show lldp neighbor"
        output = self._send_command(command, use_textfsm=True)

        data = {}

        for entry in output:
            if entry["interface"] not in data:
                data.update({self._format_interface_name(entry["interface"]): []})
            data[self._format_interface_name(entry["interface"])].append(
                {
                    "hostname": entry["hostname"],
                    "port": entry["port"],
                }
            )

        return data

    def get_lldp_neighbors_detail(self, interface=""):
        commands = {}
        if interface == "":
            command = "show lldp neighbor"
            output = self._send_command(command, use_textfsm=True)

            for entry in output:
                if "Group" in entry["interface"]:
                    entry["interface"] = entry["interface"].replace(
                        "Group", "port-channel"
                    )
                commands[
                    entry["interface"]
                ] = f"show lldp neighbor {entry['interface']}"
        else:
            commands[interface] = [f"show lldp neighbor {interface}"]

        output = {}
        for k in commands:
            output[k] = self._send_command(commands[k], use_textfsm=True)

        data = {}

        for k in output:
            intf = self._format_interface_name(k)
            if intf not in data:
                data.update({intf: []})
            data[intf].append(
                {
                    "parent_interface": "",
                    "remote_chassis_id": output[k][0]["remote_chassis_id"],
                    "remote_system_name": output[k][0]["remote_system_name"],
                    "remote_port": "",
                    "remote_port_description": output[k][0]["remote_port_description"],
                    "remote_system_description": output[k][0][
                        "remote_system_description"
                    ],
                    "remote_system_capab": [],
                    "remote_system_enable_capab": [],
                }
            )

        return data

    def get_ntp_servers(self):
        command = "show ntp"
        output = self._send_command(command, use_textfsm=True)

        data = {}

        for entry in output:
            data[entry["ntp"]] = {}

        return data

    def get_optics(self):
        command = "show transceiver"
        output = self._send_command(command, use_textfsm=True)

        data = {}

        for entry in output:
            data.update(
                {
                    self._format_interface_name(entry["interface"]): {
                        "physical_channels": {
                            "channel": [
                                {
                                    "index": 0,
                                    "state": {
                                        "input_power": {
                                            "instant": float(
                                                entry["input_power_instant"]
                                            ),
                                            "avg": -1.0,
                                            "min": -1.0,
                                            "max": -1.0,
                                        },
                                        "output_power": {
                                            "instant": float(
                                                entry["output_power_instant"]
                                            ),
                                            "avg": -1.0,
                                            "min": -1.0,
                                            "max": -1.0,
                                        },
                                        "laser_bias_current": {
                                            "instant": float(
                                                entry["laser_bias_current_instant"]
                                            ),
                                            "avg": -1.0,
                                            "min": -1.0,
                                            "max": -1.0,
                                        },
                                    },
                                }
                            ]
                        }
                    }
                }
            )

        return data

    def get_route_to(self, destination="", protocol="", longer=False):
        commands = ["show ip route", "show ipv6 route"]
        output = {}
        for command in commands:
            output[command] = self._send_command(command, use_textfsm=True)

        data = {}

        for command in commands:
            for entry in output[command]:
                if (
                    protocol == ""
                    or protocol.lower() == self._get_protocol(entry["protocol"]).lower()
                    and (destination == "" or destination == entry["destination"])
                ):
                    if entry["destination"] not in data:
                        data[entry["destination"]] = []
                    data[entry["destination"]].append(
                        {
                            "protocol": self._get_protocol(entry["protocol"]),
                            "inactive_reason": "Local Preference",
                            "last_active": False,
                            "age": -1,
                            "next_hop": entry["next_hop"],
                            "selected_next_hop": False,
                            "preference": int(entry["preference"])
                            if entry["preference"]
                            else 0,
                            "current_active": False,
                            "outgoing_interface": entry["outgoing_interface"],
                            "routing_table": "global",
                            "protocol_attributes": {},
                        }
                    )

        return data

    def get_snmp_information(self):
        commands = ["show snmp-server", "show snmp-server engineID"]
        output = {}
        for command in commands:
            output[command] = self._send_command(command, use_textfsm=True)

        data = {
            "chassis_id": output["show snmp-server engineID"][0]["engine_id"],
            "community": {},
            "contact": output["show snmp-server"][0]["contact"],
            "location": output["show snmp-server"][0]["location"],
        }

        for community in output["show snmp-server"][0]["community"]:
            data["community"][community.split(",")[0]] = {
                "acl": "",
                "mode": "ro" if "read-only" in community else "rw",
            }

        return data

    def get_users(self):
        command = "show users"
        output = self._send_command(command, use_textfsm=True)

        data = {}

        for entry in output:
            data[entry["username"]] = {
                "level": int(entry["level"]),
                "password": "",
                "sshkeys": [],
            }

        return data

    def get_vlans(self):
        command = "show vlan all"
        output = self._send_command(command, use_textfsm=True)

        data = {}

        for entry in output:
            data[entry["id"]] = {
                "name": entry["name"],
                "interfaces": [
                    self._format_interface_name(interface)
                    for interface in entry["interfaces"]
                ],
            }

        return data

    def is_alive(self):
        null = chr(0)
        if self.device is None:
            return {"is_alive": False}
        try:
            # Try sending ASCII null byte to maintain the connection alive
            self.device.write_channel(null)
            return {"is_alive": self.device.remote_conn.transport.is_active()}
        except (socket.error, EOFError):
            # If unable to send, we can tell for sure that the connection is unusable
            return {"is_alive": False}

    def ping(
        self,
        destination,
        source="",
        ttl=255,
        timeout=2,
        size=100,
        count=5,
        vrf="",
        source_interface="",
    ):
        command = f"ping {self._get_ip_version(destination)} {destination} size {size} count {count}"
        output = self._send_command(command, use_textfsm=True)[0]

        data = {}

        if int(output["packet_sent"]) == int(output["packet_lost"]):
            data["error"] = f"unknown host {destination}"
        else:
            data["success"] = {
                "probes_sent": int(output["packet_sent"]),
                "packet_loss": int(output["packet_lost"]),
                "rtt_min": float(output["rtt_min"]),
                "rtt_max": float(output["rtt_max"]),
                "rtt_avg": float(output["rtt_avg"]),
                "rtt_stddev": -1.0,
                "results": [
                    {"ip_address": destination, "rtt": float(output["rtt_avg"])}
                ],
            }

        return data

    def traceroute(self, destination, source="", ttl=255, timeout=2, vrf=""):
        command = f"traceroute {self._get_ip_version(destination)} {destination}"
        output = self._send_command(command, use_textfsm=True)[0]

        data = {}

        if output["status"] != "Trace completed":
            data["error"] = f"unknown host {destination}"
        else:
            data["success"] = {}
            for i in range(0, len(output["ip"])):
                if output["ip"][i] != "None":
                    data["success"][i + 1] = {"probes": {}}
                    for j in range(1, 4):
                        if output[f"rtt{j}"][i] != "*":
                            data["success"][i + 1]["probes"][j] = {
                                "rtt": float(output[f"rtt{j}"][i]),
                                "ip_address": output["ip"][i],
                                "host_name": "",
                            }

        return data
