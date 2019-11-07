import ipaddress


class FgInterface:
    """FgInterface class represents FortiGate Firewall interface object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications

    Currently supports interface types of \"standard\" i.e. ethernet/physical, vlan and vdom-link"""

    def __init__(self, intf: str = None, ip: str = None, ipv6: str = None, mode: str = None, modeipv6: str = None,
                 intf_type: str = None,  vdom: str = None, vrf: int = 0, allowaccess: str = None,
                 role: str = None, vlanid: int = None, phys_intf: str = None, device_ident: bool = False,
                 alias: str = None, description: str = None):

        # Set Instance "constants"
        self.API = 'cmdb'
        self.PATH = 'system'
        self.NAME = 'interface'
        self.MKEY = None

        # Set Instance Variables
        self.set_intf(intf)
        self.set_ip(ip)
        self.set_ipv6(ipv6)
        self.set_mode(mode)
        self.set_modeipv6(modeipv6)
        self.set_interface_type(intf_type)
        self.set_vdom(vdom)
        self.set_vrf(vrf)
        self.set_allowaccess(allowaccess)
        self.set_role(role)
        self.set_vlanid(vlanid)
        self.set_phys_intf(phys_intf)
        self.set_device_ident(device_ident)
        self.set_alias(alias)
        self.set_description(description)

    @classmethod
    def standard_intf(cls, intf: str, ip: str = None, ipv6: str = None, mode: str = 'static', modeipv6: str = None,
                      vdom: str = None, vrf: int = None, allowaccess: str = None, role: str = None,
                      device_ident: bool = None, alias: str = None, description: str = None):

        intf_type = None
        vlanid = None
        phys_intf = None

        obj = cls(intf, ip, ipv6, mode, modeipv6, intf_type, vdom, vrf, allowaccess, role, vlanid, phys_intf,
                  device_ident, alias, description)

        return obj

    @classmethod
    def vlan_intf(cls, intf: str, vlanid: int, phys_intf: str, ip: str = None, ipv6: str = None, mode: str = 'static',
                  modeipv6: str = None, vdom: str = None, vrf: int = None, allowaccess: str = None,
                  role: str = None, device_ident: bool = None, alias: str = None, description: str = None):

        if not vlanid: raise Exception("\"vlan_intf()\", requires to provide a \"vlanid\". vlanid should be type: int, "
                                       "between 1 and 4960")

        if not phys_intf: raise Exception("\"vlan_intf\", requires to provide \"phys_intf\", phys_intf should be type: "
                                          "str between 1 and 15 chars")

        intf_type = 'vlan'

        obj = cls(intf, ip, ipv6, mode, modeipv6, intf_type, vdom, vrf, allowaccess, role, vlanid, phys_intf,
                  device_ident, alias, description)

        return obj

    @classmethod
    def vdom_link_intf(cls, name: str):

        intf_type = 'vdom-link'
        obj = cls(intf_type=intf_type, intf=name)

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
        self.ip = ipaddress.ip_interface(ip) if ip else None

    def set_ipv6(self, ipv6):
        self.ipv6 = ipaddress.IPv6Interface(ipv6) if ipv6 else None

    def set_interface_type(self, intf_type):
        if intf_type:
            if intf_type.lower() == 'vlan':
                self.type = 'vlan'
            elif intf_type.lower() == 'standard':
                self.type = None
            elif intf_type.lower() == 'vdom-link':
                self.type = 'vdom-link'
                self.NAME = 'vdom-link'
            elif intf_type.lower() == 'loopback':
                self.type = 'loopback'
            elif not intf_type:
                self.type = None
            else:
                raise Exception("Interface type provided is not recognized: {}".format(intf_type))
        else:
            self.type = None

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

    def set_modeipv6(self, modeipv6):
        if modeipv6:
            if modeipv6.lower() == 'dhcp':
                self.ipv6mode = 'dhcp'
            elif modeipv6.lower() == 'static':
                self.ipv6mode = 'static'
            else:
                raise Exception("If set, mode, must be set to either dhcp or static")
        else:
            self.ipv6mode = 'static'

    def set_vdom(self, vdom):
        if vdom:
            for char in vdom:
                if str.isspace(char): raise Exception("\"vdom\", str not allowed to contain whitespace")

            if isinstance(vdom, str):
                if 1 <= len(vdom) <= 31:
                    self.vdom = vdom
                else:
                    raise Exception("\"vdom\", when set, must be an str between 1 and 31 chars")
            else:
                raise Exception("\"vdom\", when set, must be a str")
        else:
            self.vdom = None

    def set_allowaccess(self, allowaccess):
        if allowaccess:
            for service in list(allowaccess.split(" ")):
                if service.lower() in ['ping', 'http', 'https', 'snmp', 'ssh', 'telnet', 'fgfm', 'radius=acct',
                                       'probe-response', 'capwap', 'ftm']:
                    continue
                else:
                    raise Exception("Param \"allowaccces\" has unrecognized services defined: {}".format(service))
            self.allowacess = allowaccess
        else:
            self.allowacess = None

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

    def get_cli_config_add(self):
        conf = ''

        # If type is vdom link, we configure from global.  You mus then configure the vdom-link endpoints as
        # separate individual interfaces <name>_0 and <name>_1, as this just creates the endpoints.
        if self.type == 'vdom-link':
            print("***** type: {}".format(self.type))
            conf += "config global\n"
            conf += "  config system vdom-link\n"
            conf += "   edit {}\n".format(self.intf)
            conf += "  end\nend\n"

            return conf

        # If vdom was set, then enter vdom context
        if self.vdom: conf += "config vdom\n  edit {}\n".format(self.vdom)
        conf += "config system interface\n  edit \"{}\"\n".format(self.intf)
        if self.vdom: conf += "    set vdom {}\n".format(self.vdom)

        if self.type == 'vlan' and self.vlanid and self.phys_intf:
            conf += "    set type vlan\n"
            conf += "    set vlanid {}\n".format(self.vlanid)
            conf += "    set interface \"{}\"\n".format(self.phys_intf)

        # If mode static, set the interface ip address
        if isinstance(self.ip, ipaddress.IPv4Interface) and self.mode == 'static':
            conf += "    set mode static\n"
            conf += "    set ip {}\n".format(self.ip)

        # This isn't necessarily required in FOS, but to avoid errors, here we ensure that if setting to static
        # that we also have a valid ipv4 address/mask (as checked in if statement above) if not raise error.
        elif self.mode == 'static':
            raise Exception("\"mode\" is set to static but a valid ipv4 ip.netmask was not provided, {}"
                            .format(self.ip))
        else:
            conf += "    set mode dhcp\n"

        # Set other interface params as necessary
        if self.allowacess: conf += "    set allowaccess {}\n".format(self.allowacess)
        if self.vrf: conf += "    set vrf {}\n".format(self.vrf)
        if self.device_ident: conf += "    set device-identification enable\n"
        if self.alias: conf += "    set alias \"{}\"\n".format(self.alias)
        if self.description: conf += "    set description \"{}\"\n".format(self.description)
        if self.role: conf += "    set role {}\n".format(self.role)

        if isinstance(self.ipv6, ipaddress.IPv6Interface) and self.ipv6mode == 'static':
            conf += "    config ipv6\n"
            conf += "      set ip6-mode static\n"
            conf += "      set ip6-address {}\n".format(self.ipv6)
            conf += "    end\n"

        elif self.ipv6mode == 'dhcp':
            conf += "    config ipv6\n"
            conf += "      set ip6-mode dhcp\n"
            conf += "    end\n"

        # End interface configuration
        conf += "  end\nend\n"

        # End vdom configuration
        if self.vdom: conf += "end\n"

        return conf

    def get_cli_config_update(self):
        conf = self.get_cli_config_add()
        return conf

    def get_api_config_add(self):
        conf = {'api': self.API, 'path': self.PATH, 'name': self.NAME, 'mkey': self.MKEY, 'action': None}
        data = {}
        params = {}
        data.update({'name': self.intf})

        # If this is a type vdom-link then create /system/vdom-link.  This will create two endpoint interfaces;
        # those endpoint interfaces <vlink name>_0 and <vlink_name>_1 must be configured as separately, using
        # type "vlink-member".
        if self.type == 'vdom-link':
            conf.update({'data': data})
            conf.update({'parameters': params})
            return conf

        # Set the VDOM, if necessary
        if self.vdom:
            params.update({'vdom': self.vdom})
            data.update({'vdom': self.vdom})

        # Add vlan data
        if self.type == 'vlan' and self.vlanid and self.phys_intf:
            data.update({'type': 'vlan'})
            data.update({'vlanid': self.vlanid})
            data.update({'interface': self.phys_intf})

        # Add interface type and ip data
        if isinstance(self.ip, ipaddress.IPv4Interface) and self.mode == 'static':
            data.update({'mode': 'static'})
            data.update({'ip': str(self.ip)})

        elif self.mode == 'static':
            raise Exception("\"mode\" is set to static but a valid ipv4 ip.netmask was not provided, {}"
                            .format(self.ip))
        else:
            data.update({'mode': 'dhcp'})

        # Add other settings if necessary
        if self.allowacess: data.update({'allowaccess': self.allowacess})
        if self.vrf: data.update({'vrf': self.vrf})
        if self.device_ident: data.update({'device-identification': 'enable'})
        if self.alias: data.update({'alias': self.alias})
        if self.description: data.update({'description': self.description})
        if self.role: data.update({'role': self.role})

        # Set IPv6 related vars if necessary
        if isinstance(self.ipv6, ipaddress.IPv6Interface) and self.ipv6mode == 'static':
            data.update({'ipv6': []})
            data['ipv6'].update({'ip6-mode': 'static'})
            data['ipv6'].update({'ip6-address': str(self.ipv6)})

        elif self.ipv6mode == 'dhcp':
            data.update({'ipv6': []})
            data['ipv6'].update({'ip6-mode': 'dhcp'})

        # Add data and parameter dicts to the return dict
        conf.update({'data': data})
        conf.update({'parameters': params})

        return conf

    def get_api_config_update(self):
        # Need to set mkey to interface name when doing updates (puts) or deletes
        self.MKEY = self.intf

        conf = self.get_api_config_add()
        return conf

    def get_cli_config_del(self):
        conf = ''
        if self.intf:
            if self.vdom: conf += "config vdom\nedit {}\n".format(self.vdom)
            conf += "config system interface\n"
            conf += "delete {}\n".format(self.intf)
            conf += "end\n"
            if self.vdom: conf += "end\n"
            return conf
        else:
            raise Exception("Interface name \"intf\" must be set in order to configure it for delete")

    def get_api_config_del(self):
        """
        :param self:
        :return: conf:
        """
        conf = {'api': self.API, 'path': self.PATH, 'name': self.NAME, 'mkey': self.MKEY, 'action': None}
        data = {}
        params = {}

        if self.intf:
            # Set the mkey value to interface name and updated other dictionaries
            data['mkey'] = self.intf
            conf.update({'data': data})
            conf.update({'parameters': params})

        else:
            raise Exception("Interface name \"intf\" must be set in order to configure it for delete ")

        return conf

    def get_api_config_get(self):
        conf = self.get_api_config_del()
        return conf