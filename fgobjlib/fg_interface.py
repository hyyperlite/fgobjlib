from fgobjlib import FgObject
import ipaddress


class FgInterfaceIpv4(FgObject):
    """
    FgInterface class represents FortiGate Firewall interface object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications

    Currently supports interface types of \"standard\" i.e. ethernet/physical or vlan,
    """

    def __init__(self, intf: str = None, ip: str = None, mode: str = None, intf_type: str = None,  vdom: str = None,
                 vrf: int = None, allowaccess: str = None, role: str = None, vlanid: int = None, phys_intf: str = None,
                 device_ident: bool = None, alias: str = None, description: str = None):

        # Set Instance Variables
        self.set_intf(intf)
        self.set_ip(ip)
        self.set_mode(mode)
        self.set_intf_type(intf_type)
        self.set_vrf(vrf)
        self.set_allowaccess(allowaccess)
        self.set_role(role)
        self.set_vlanid(vlanid)
        self.set_phys_intf(phys_intf)
        self.set_device_ident(device_ident)
        self.set_alias(alias)
        self.set_description(description)

        # Initialize the parent class
        super().__init__(vdom=vdom, api='cmdb', api_path='system', api_name='interface', api_mkey=None,
                         obj_id=self.intf)

        ### Set parent class attributes ###
        # CLI config path for this object type
        self.cli_path = "config system interface"

        # Map instance attribute names to fg attribute names
        self.data_attrs = {'intf': 'name', 'ip': 'ip', 'vdom': 'vdom', 'intf_type': 'type', 'vrf': 'vrf',
                           'allowaccess': 'allowaccess', 'role': 'role', 'vlanid': 'vlanid',
                           'phys_intf': 'interface', 'device_ident': 'device-identification',
                           'alias': 'alias', 'description': 'description'}

        self.cli_ignore_attrs = ['intf']

    @classmethod
    def standard_intf(cls, intf: str, ip: str = None, mode: str = 'static', vdom: str = None, vrf: int = None,
                      allowaccess: str = None, role: str = None, device_ident: bool = None, alias: str = None,
                      description: str = None):

        intf_type = None
        vlanid = None
        phys_intf = None

        obj = cls(intf, ip, mode, intf_type, vdom, vrf, allowaccess, role, vlanid, phys_intf,
                  device_ident, alias, description)

        return obj

    @classmethod
    def vlan_intf(cls, intf: str, vlanid: int, phys_intf: str, ip: str = None, mode: str = 'static', vdom: str = None,
                  vrf: int = None, allowaccess: str = None, role: str = None, device_ident: bool = None,
                  alias: str = None, description: str = None):

        if not vlanid: raise Exception("\"vlan_intf()\", requires to provide a \"vlanid\". vlanid should be type: int, "
                                       "between 1 and 4960")

        if not phys_intf: raise Exception("\"vlan_intf\", requires to provide \"phys_intf\", phys_intf should be type: "
                                          "str between 1 and 15 chars")

        intf_type = 'vlan'

        obj = cls(intf, ip, mode, intf_type, vdom, vrf, allowaccess, role, vlanid, phys_intf,
                  device_ident, alias, description)

        return obj

    def set_intf(self, intf):
        if intf:
            if intf.isspace(): raise Exception("\"intf\", cannot be an empty string")
            if isinstance(intf, str):
                if len(intf) < 15:
                    self.intf = intf
                else:
                    raise Exception("\"intf\", must be less than 15 chars")
            else:
                raise Exception("\"intf\", must be a string")
        else:
            raise Exception("Value \"intf\" is required but was not provided")

    def set_ip(self, ip):
        if ip:
            try:
                self.ip = str(ipaddress.ip_interface(ip))
            except ValueError:
                raise ValueError("\ip\" must be valide ipv4 address")
        else:
            self.ip = None

    def set_intf_type(self, intf_type):
        if intf_type:
            if intf_type.lower() == 'vlan':
                self. intf_type = 'vlan'
            elif intf_type.lower() == 'standard':
                self.intf_type = None
            elif intf_type.lower() == 'loopback':
                self.intf_type = 'loopback'
            else:
                raise Exception("Interface type provided is not recognized: {}".format(intf_type))
        else:
            self.intf_type = None

    def set_role(self, role):
        if role:
            if role.lower == 'wan':
                self.role = 'wan'
            elif role.lower() == 'lan':
                self.role = 'lan'
            elif role.lower() == 'dmz':
                self.role = 'dmz'
            else:
                self.role = 'undefined'
        else:
            self.role = None

    def set_mode(self, mode):
        if mode:
            if mode.lower() == 'dhcp':
                self.mode = 'dhcp'
            elif mode.lower() == 'static':
                self.mode = 'static'
            else:
                raise Exception("If set, \"mode\", must be set to either dhcp or static")
        else:
            self.mode = 'dhcp'

    def set_allowaccess(self, allowaccess):
        if allowaccess:
            for service in list(allowaccess.split(" ")):
                if service.lower() in ['ping', 'http', 'https', 'snmp', 'ssh', 'telnet', 'fgfm', 'radius=acct',
                                       'probe-response', 'capwap', 'ftm']:
                    continue
                else:
                    raise Exception("\"allowaccces\" has unrecognized services defined: {}".format(service))
            self.allowaccess = allowaccess
        else:
            self.allowaccess = None

    def set_vlanid(self, vlanid):
        if vlanid:
            if isinstance(vlanid, int):
                if 1 <= vlanid <= 4096:
                    self.vlanid = vlanid
                else:
                    raise Exception("vlanid must be integer between 1 and 4096")
            else:
                raise Exception("vlanid, when set, must be an integer")
        else:
            self.vlanid = None

    def set_phys_intf(self, phys_intf):
        if phys_intf:
            if phys_intf.isspace():
                raise Exception("\"phys_intf\" cannot be an empty string")

            if isinstance(phys_intf, str):
                if 1 <= len(phys_intf) <= 31:
                    self.phys_intf = phys_intf
                else:
                    raise Exception("\"phys_intf\", when set, must be type str between 1 and 31 chars")
            else:
                raise Exception("\"phys_intf\", when set, must be type str")
        else:
            self.phys_intf = None

    def set_vrf(self, vrf):
        if vrf:
            if isinstance(vrf, int):
                if 0 <= vrf <= 31:
                    self.vrf = vrf
                else:
                    raise Exception("\"vrf\", when set, must be an integer between 0 and 31")
            else:
                raise Exception("\"vrf\", when set, must be an integer between 0 and 31")
        else:
            self.vrf = None

    def set_device_ident(self, device_ident):
        if device_ident:
            if isinstance(device_ident, bool):
                self.device_ident = True
        else:
            self.device_ident = False

    def set_alias(self, alias):
        if alias:
            if isinstance(alias, str):
                if 1 <= len(alias) <= 25:
                    self.alias = alias
                else:
                    raise Exception("\"alias\", when set, must be type str between 1 and 25 chars")
            else:
                raise Exception("\"alias\", when set, must be type str")
        else:
            self.alias = None

    def set_description(self, description):
        if description:
            if isinstance(description, str):
                if 1 <= len(description) <= 255:
                    self.description = description
                else:
                    raise Exception("\"description\", when set, must be type str between 1 and 255 chars")
            else:
                raise Exception("\"description\", when set, must be type str")
        else:
            self.description = None
