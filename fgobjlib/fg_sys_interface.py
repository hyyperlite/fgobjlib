from fgobjlib import FgObject
import ipaddress


class FgInterfaceIpv4(FgObject):
    """
    FgInterface class represents FortiGate Firewall interface object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications

    Currently supports interface types of "standard" i.e. ethernet/physical or vlan

    Attributes:
        name (str): Name of interface
        ip (str): IP address of interface
        mode (str): Interface mode, i.e. static or dhcp
        intf_type (str): Interface type, i.e. physical/virtual (default) or vlan
        vdom (str): Vdom interface configured for
        vrf (int): VRF interface is configured for
        allowaccess (str):  Interface allowaccess policy.  i.e. "ping http, https snmp, etc"
        role (str):  Interface role type
        vlanid (str): Interface vlanid
        phys_intf (str): Interfaces physical intf attachment.  (if intf_type is vlan)
        device_ident (str): device-identification ('enable', 'disable', or None=inherit)
        alias (str): Interface alias
        description (str): Interface description
    """

    def __init__(self, name: str = None, ip: str = None, mode: str = None, intf_type: str = None, vdom: str = None,
                 vrf: int = None, allowaccess: str = None, role: str = None, vlanid: int = None, phys_intf: str = None,
                 device_ident: str = None, alias: str = None, description: str = None, is_global: bool = None):
        """
        Args:
            name (str): Name of interface
            ip (str): IP address of interface
            mode (str): Interface mode, i.e. static or dhcp
            intf_type (str): Interface type, i.e. physical/virtual (default) or vlan
            vdom (str): Vdom interface configured for
            vrf (int): VRF interface is configured for
            allowaccess (str):  Interface allowaccess policy.  i.e. "ping http, https snmp, etc"
            role (str):  Interface role type
            vlanid (str): Interface vlanid
            phys_intf (str): Interfaces physical intf attachment.  (if intf_type is vlan)
            device_ident (str): device-identification  ('enable', 'disable', or None=inherit)
            alias (str): Interface alias
            description (str): Interface description
        """

        # Initialize the parent class
        super().__init__(api='cmdb', api_path='system', api_name='interface', cli_path="config system interface",
                         obj_id=name, vdom=vdom)

        ### Set parent class attributes ###
        # Map instance attribute names to fg attribute names
        self.data_attrs = {'name': 'name', 'ip': 'ip', 'vdom': 'vdom', 'intf_type': 'type', 'vrf': 'vrf',
                           'allowaccess': 'allowaccess', 'role': 'role', 'vlanid': 'vlanid',
                           'phys_intf': 'interface', 'device_ident': 'device-identification',
                           'alias': 'alias', 'description': 'description'}

        # Attributes to ignore for cli config
        self.cli_ignore_attrs = ['name']

        # For objects types that can be configured from global or vdom context,
        # set is_global = True if need to config from global context instead of vdom
        self.is_global = is_global

        # Set instance attributes
        self.set_name(name)
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

        # Update the parent defined obj_to_str attribute with this objects str representation
        self.obj_to_str += f', name={self.name}, ip={self.ip}, mode={self.mode}, intf_type={self.intf_type}, ' \
                          f'vrf={self.vrf}, allowaccess={self.allowaccess}, role={self.role}, vlanid={self.vlanid}, ' \
                          f'phys_intf={self.phys_intf}.device_ident={self.device_ident}, alias={self.alias}, ' \
                          f'description={self.description}, vdom={self.vdom}'



    # Class Methods
    @classmethod
    def standard_intf(cls, name: str, ip: str = None, mode: str = None, vdom: str = None, vrf: int = None,
                      allowaccess: str = None, role: str = None, device_ident: bool = None, alias: str = None,
                      description: str = None):
        """ Class method to streamline instantiating instance of type "standard" aka ethernet/virtual/physical

        Args:
            name (str): Name of interface
            ip (str): IP address of interface
            mode (str): Interface mode, i.e. static or dhcp
            vdom (str): Vdom interface configured for
            vrf (int): VRF interface is configured for
            allowaccess (str):  Interface allowaccess policy.  i.e. "ping http, https snmp, etc"
            role (str):  Interface role type
            device_ident (str): device-identification  ('enable', 'disable', or None=inherit)
            alias (str): Interface alias
            description (str): Interface description

        Returns:
            Class Instance
        """

        intf_type = None
        vlanid = None
        phys_intf = None

        obj = cls(name=name, ip=ip, mode=mode, intf_type=intf_type, vdom=vdom, vrf=vrf, allowaccess=allowaccess,
                  role=role, vlanid=vlanid, phys_intf=phys_intf, device_ident=device_ident, alias=alias,
                  description=description)

        return obj

    @classmethod
    def vlan_intf(cls, name: str, vlanid: int, phys_intf: str, ip: str = None, mode: str = 'static', vdom: str = None,
                  vrf: int = None, allowaccess: str = None, role: str = None, device_ident: bool = None,
                  alias: str = None, description: str = None):
        """ Class method to streamline instantiating instance of type vlan

        Args:
            name (str): Name of interface
            vlanid (int): interface vlanid
            phys_intf (str): name of parent interface for vlan attachment
            ip (str): IP address of interface
            mode (str): Interface mode, i.e. static or dhcp
            vdom (str): Vdom interface configured for
            vrf (int): VRF interface is configured for
            allowaccess (str):  Interface allowaccess policy.  i.e. "ping http, https snmp, etc"
            role (str):  Interface role type
            device_ident (str): device-identification  ('enable', 'disable', or None=inherit)
            alias (str): Interface alias
            description (str): Interface description

        Returns:
            Class Instance
        """

        if not vlanid: raise Exception("'vlan_intf()', requires to provide a 'vlanid'. vlanid should be type: int, "
                                       "between 1 and 4960")

        if not phys_intf: raise Exception("'vlan_intf', requires to provide 'phys_intf', phys_intf should be type: "
                                          "str between 1 and 15 chars")

        intf_type = 'vlan'

        obj = cls(name=name, ip=ip, mode=mode, intf_type=intf_type, vdom=vdom, vrf=vrf, allowaccess=allowaccess,
                  role=role, vlanid=vlanid, phys_intf=phys_intf, device_ident=device_ident, alias=alias,
                  description=description)

        return obj

    # Instance Methods
    def set_name(self, name):
        """ Set self.name to name if name meets requirements

        Args:
            name (str): Interface name to set.

        Returns:
            None
        """
        if name is None:
            self.name = None

        else:
            if isinstance(name, str):
                if name.isspace(): raise Exception("'name', cannot be an empty string")

                if len(name) < 15:
                    self.name = name
                else:
                    raise Exception("'name', must be less than 15 chars")
            else:
                raise Exception("'name', must be a string")

    def set_ip(self, ip):
        """ Set self.ip as IP address for interface if IP is valid ipv4 address.  Otherwise raise Exception.

        Args:
            ip: Interface IPv4 address to set.  Must be valid IP/netmask.  IP without netmask = /32

        Returns:
            None
        """
        if ip is None:
            self.ip = None

        else:
            try:
                self.ip = str(ipaddress.ip_interface(ip))
            except ValueError:
                raise ValueError("'ip' must be a valid ipv4 address")

    def set_intf_type(self, intf_type):
        """ Set self.intf_type if intf type matches allowed types

        Args:
            intf_type (str): Interface type to set.  May be: 'vlan', 'standard', 'loopback', None (default standard or existing setting)

        Returns:
            None
        """
        if intf_type is None:
            self.intf_type = None

        else:
            if isinstance(intf_type, str):
                if intf_type.lower() == 'vlan':
                    self. intf_type = 'vlan'
                elif intf_type.lower() == 'standard':
                    self.intf_type = None
                elif intf_type.lower() == 'loopback':
                    self.intf_type = 'loopback'
                else:
                    raise ValueError(f"Interface type provided is not recognized: {intf_type}")
            else:
                raise ValueError("'intf_type', when set, must be type str")

    def set_role(self, role):
        """ Set self.role if role matches allowed role types.

        Args:
            role (str): Interface role to set.   Allowed types:  'wan', 'lan', 'dmz', 'undefined', None (use existing setting)

        Returns:

        """
        if role is None:
            self.role = None

        else:
            if isinstance(role, str):
                if role.lower() == 'wan':
                    self.role = 'wan'
                elif role.lower() == 'lan':
                    self.role = 'lan'
                elif role.lower() == 'dmz':
                    self.role = 'dmz'
                else:
                    self.role = 'undefined'
            else:
                raise ValueError("'role', when set, must be type str")

    def set_mode(self, mode):
        """ Set self.mode to mode if mode set with valid argument

        Args:
            mode (str): Interface Mode to set.   May be: 'dhcp', 'static', None (None uses existing intf setting)

        Returns:
            None
        """
        if mode is None:
            self.mode = 'dhcp'

        else:
            if isinstance(mode, str):
                if mode.lower() == 'dhcp':
                    self.mode = 'dhcp'
                elif mode.lower() == 'static':
                    self.mode = 'static'
                else:
                    raise ValueError("'mode', when set,  must be set to either 'dhcp' or 'static'")
            else:
                raise ValueError("'mode', when set, must be type str")

    def set_allowaccess(self, allowaccess):
        """ Set self.allowaccess  to allowaccess if allowaccess contains allowed params

        Args:
            allowaccess (str): Interface mgmt access setting. Single string with spaces to separate multiple values

        Returns:
            None
        """
        if allowaccess is None:
            self.allowaccess = None

        else:
            if isinstance(allowaccess, str):
                for service in list(allowaccess.split(" ")):
                    if service.lower() in ['ping', 'http', 'https', 'snmp', 'ssh', 'telnet', 'fgfm', 'radius=acct',
                                           'probe-response', 'capwap', 'ftm']:
                        continue
                    else:
                        raise ValueError(f"'allowaccces' has unrecognized services defined: {service}")
            else:
                raise ValueError("'allowaccess', when set, must be type str")

            self.allowaccess = allowaccess

    def set_vlanid(self, vlanid):
        """  Set self.vlanid if vlanid is valid

        Args:
            vlanid: Interface vlanid to set.  Must be between 1 and 4096

        Returns:
            None
        """
        if vlanid is None:
            self.vlanid = None

        else:
            if isinstance(vlanid, int):
                if 1 <= vlanid <= 4096:
                    self.vlanid = vlanid
                else:
                    raise ValueError("'vlanid', when set, must be integer between 1 and 4096")
            else:
                raise ValueError("vlanid, when set, must be an integer")

    def set_phys_intf(self, phys_intf):
        """ Set self.phys_intf to phys_intf if phys_intf valid

        Args:
            phys_intf (str): Parent interface for virtual interface type, such as vlan to set.

        Returns:
            None
        """
        if phys_intf is None:
            self.phys_intf = None

        else:
            if isinstance(phys_intf, str):
                if phys_intf.isspace():
                    raise ValueError("'phys_intf' cannot be an empty string")

                if 1 <= len(phys_intf) <= 31:
                    self.phys_intf = phys_intf
                else:
                    raise ValueError("'phys_intf', when set, must be type str between 1 and 31 chars")
            else:
                raise ValueError("'phys_intf', when set, must be type str")

    def set_vrf(self, vrf):
        """ Set self.vrf if vrf valid

        Args:
            vrf (int): Interface VRF to set

        Returns:
            None
        """
        if vrf is None:
            self.vrf = None

        else:
            if isinstance(vrf, int):
                if 0 <= vrf <= 31:
                    self.vrf = vrf
                else:
                    raise Exception("'vrf', when set, must be an integer between 0 and 31")
            else:
                raise Exception("'vrf', when set, must be an integer between 0 and 31")

    def set_device_ident(self, device_ident):
        """ Set self.device_idnent if device_ident valid

        Args:
            device_ident (str): device-identification  ('enable', 'disable', or None=inherit)

        Returns:
            None
        """
        if device_ident is None:
            self.device_ident = False

        else:
            if isinstance(device_ident, str):
                if device_ident == 'enable':
                    self.device_ident = 'enable'
                elif device_ident == 'disable':
                    self.device_ident = 'disable'
                else:
                    raise ValueError("'device_ident', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'device_ident', when set, must be type str()")

    def set_alias(self, alias):
        """ Set self.alias to alias if alias valid

        Args:
            alias: Interface Alias to set

        Returns:

        """
        if alias is None:
            self.alias = None

        else:
            if isinstance(alias, str):
                if 1 <= len(alias) <= 25:
                    self.alias = alias
                else:
                    raise ValueError("'alias', when set, must be type str between 1 and 25 chars")
            else:
                raise ValueError("'alias', when set, must be type str")

    def set_description(self, description):
        """ Set self.description to description if description is valid

        Args:
            description: Interface description to set.

        Returns:
            None
        """
        if description is None:
            self.description = None

        else:
            if isinstance(description, str):
                if 1 <= len(description) <= 255:
                    self.description = description
                else:
                    raise Exception("'description', when set, must be type str between 1 and 255 chars")
            else:
                raise Exception("'description', when set, must be type str")
