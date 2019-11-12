from fgobjlib import FgObject
import ipaddress

class FgIpsecP1Interface(FgObject):
    """
    FgIpsecP1Interface class represents FortiGate Firewall ipsec phase1 interface object and provides methods for
    validating parameters and generating both cli and api configuration data for use in external configuration
    applications

    Currently supports dynamic or static VPN using psk authentication. No support yet for advpn or mode-cfg
    """

    def __init__(self, name: str = None, p1_type: str = None, local_intf: str = None, proposal: list = None,
                 ike_version: int = None, local_gw: str = None, psk: str = None, local_id: str = None,
                 remote_gw: str = None, add_route: bool = None, add_gw_route: bool = None, keepalive: int = None,
                 net_device: bool = None, comment: str = None, vdom: str = None,  tunnel_search: str = None,
                 dpd: str = None, dhgrp: list = None, nat_traversal: str = None, exchange_interface_ip: bool = None):

        # Set instance attributes
        self.set_name(name)
        self.set_p1_type(p1_type)
        self.set_local_intf(local_intf)
        self.set_proposal(proposal)
        self.set_ike_version(ike_version)
        self.set_local_gw(local_gw)
        self.set_psk(psk)
        self.set_local_id(local_id)
        self.set_remote_gw(remote_gw)
        self.set_vdom(vdom)
        self.set_comment(comment)
        self.set_add_route(add_route)
        self.set_keepalive(keepalive)
        self.set_add_gw_route(add_gw_route)
        self.set_net_device(net_device)
        self.set_tunnel_search(tunnel_search)
        self.set_dpd(dpd)
        self.set_dhgrp(dhgrp)
        self.set_nat_traversal(nat_traversal)
        self.set_exchange_interface_ip(exchange_interface_ip)

        # Initialize the parent class
        super().__init__(vdom=vdom, api='cmdb', api_path='vpn.ipsec', api_name='phase1-interface', api_mkey=None,
                         obj_id=self.name)

        ### Set parent class attributes ###
        # CLI config path for this object type
        self.cli_path = "config vpn ipsec phase1-interface"

        # Map instance attribute names to fg attribute names
        self.data_attrs = {'name': 'name', 'p1_type': 'type', 'local_intf': 'interface', 'proposal': 'proposal',
                           'ike_version': 'ike-version', 'local_gw': 'local-gw', 'psk': 'psksecret',
                           'local_id': 'localid', 'remote_gw': 'remote-gw', 'comment': 'comments',
                           'add_route': 'add-route', 'add_gw_route': 'add-gw-route', 'keepalive': 'keepalive',
                           'net_device': 'net-device', 'tunnel_search': 'tunnel-search', 'dpd': 'dpd', 'dhgrp': 'dhgrp',
                           'nat_traversal': 'nattraversal', 'exchange_interface_ip': 'exchange-interface-ip'}

        self.cli_ignore_attrs = ['name']

    def set_name(self, name):
        if name:
            if name.isspace(): raise Exception("\"name\", cannot be an empty string")
            if isinstance(name, str):
                if len(name) <= 35:
                    self.name = name
                else:
                    raise Exception("\"name\", must be less than 35 chars or less")
            else:
                raise Exception("\"name\", must be a string")
        else:
            raise Exception("Value \"name\" is required but was not provided")

    def set_proposal(self, proposal):
        valid_proposals = ['des-md5', 'des-sha', 'des-sha256', 'des-sha384', 'des-sha512', '3des-md5', '3des-sha1',
                           '3des-sha256', '3des-sha384', '3des-sha512', 'aes128-md5', 'aes128-sha1', 'aes128-sha256',
                           'aes128-sha384', 'aes128-sha512', 'aes192-md5', 'aes192-sha1', 'aes192-sha256',
                           'aes192-sha384', 'aes192-sha512', 'aes256-md5', 'aes256-sha1', 'aes256-sha256',
                           'aes256-sha384', 'aes256-sha512', 'aria128-md5', 'aria128-sha1', 'aria128-sha256',
                           'aria128-sha384', 'aria128-sha512', 'aria192-md5', 'aria192-sha1', 'aria192-sha256',
                           'aria192-sha384', 'aria192-sha512', 'aria256-md5', 'aria256-sha1', 'aria256-sha256',
                           'aria256-sha384', 'aria256-sha512', 'seed-md5', 'seed-sha1', 'seed-sha256', 'seed-sha384',
                           'seed-sha512']

        if proposal:
            proposal_items = ''

            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list
            if isinstance(proposal, str):

                # compare proposal to valid_proposals list
                if proposal in valid_proposals:
                    proposal_items += "{} ".format(proposal)
                else:
                    raise Exception("\"proposal\" provided: {} is not a valid fortigate phase1 proposal "
                                    "option".format(proposal))

            elif isinstance(proposal, list):
                for item in proposal:
                    if isinstance(item, str):

                        # compare proposal to valid proposals list
                        if item in valid_proposals:
                            proposal_items += "{} ".format(item)
                        else:
                            raise Exception("\"proposal\" provided: {} is not a valid fortigate phase1 proposal "
                                            "option".format(proposal))
            else:
                raise Exception("proposal must be provided as type string (with single proposal referenced or as a "
                                "list for multiple proposal references")

            self.proposal = proposal_items

        else:
            self.proposal = ['3des-md5']

    def set_dhgrp(self, dhgrp):
        """
        set_dhgrp: the dhgrp may be passed in as a str, or a list.  If the dhgrp(s) passed in are valid we'll add each
        of those to a space separated values string and set in self.dhgrp
        """
        if dhgrp:
            dhgrp_items = ''
            valid_dhgrps = [1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 30, 31, 32]

            # IF a single object was passed as a string, append it to list else iterate the list and pull
            # out the dhgrps and add to list to be set as self object
            if isinstance(dhgrp, int):
                # compare proposal to valid_list
                if dhgrp in valid_dhgrps:
                    dhgrp_items += "{} ".format(dhgrp)
                else:
                    raise Exception("\"dhgrp\" provided: \"{}\", is not a valid fortigate dhgrp".format(dhgrp))

            elif isinstance(dhgrp, list):
                for item in dhgrp:
                    if isinstance(item, int):

                        # compare proposal to valid proposals list
                        if item in valid_dhgrps:
                            dhgrp_items += "{} ".format(item)
                        else:
                            raise Exception("At least one \"dhgrp\" provided: {} is not a valid fortigate phase1 "
                                            "proposal option".format(dhgrp))
            else:
                raise Exception("dhgrp must be provided as type integer")

            self.dhgrp = dhgrp_items

        else:
            self.dhgrp = None

    def set_p1_type(self, p1_type):
        if p1_type:
            if isinstance(p1_type, str):
                if p1_type.lower() == 'dynamic':
                    self.p1_type = 'dynamic'
                elif p1_type.lower() == 'static':
                    self.p1_type = 'static'
                elif p1_type.lower() == 'ddns':
                    raise Exception("p1_type of \"ddns\" is not yet supported")
                else:
                    raise Exception("\"p1_type\": {} is not supported".format(p1_type))
            else:
                raise Exception("\"p1_type\" when set must be a str with value \"dynamic\" or \"static\"")
        else:
            self.p1_type = None

    def set_local_intf(self, intf):
        if intf:
            if intf.isspace(): raise Exception("\"local_intf\", cannot be an empty string")
            if isinstance(intf, str):
                if len(intf) < 35:
                    self.local_intf = intf
                else:
                    raise Exception("\"local_intf\", must be less than 35 chars or less")
            else:
                raise Exception("\"local_intf\", must be a string")
        else:
            raise Exception("\"local_intf\" not set, phase1 requires to define the interface")

    def set_ike_version(self, ike_version):
        if ike_version:
            if isinstance(ike_version, int):
                if ike_version == 1:
                    self.ike_version = 1
                elif ike_version == 2:
                    self.ike_version = 2
                else:
                    raise Exception("\"ike_version\", when set must be type int with value = \"1\" or \"2\"")
            else:
                raise Exception("\"ike_version\" when set, must be type int with value = \"1\" or \"2\"")
        else:
            self.ike_version = None

    def set_local_gw(self, local_gw):
        if local_gw:
            try:
                ipaddress.ip_address(local_gw)
            except ValueError:
                print("\"local_gw\", must be a valid ipv4 or ipv6 address")
            else:
                self.local_gw = local_gw
        else:
            self.local_gw = None

    def set_remote_gw(self, remote_gw):
        if remote_gw:
            try:
                ipaddress.ip_address(remote_gw)
            except ValueError:
                print("\"remote_gw\", must be a valid ipv4 or ipv6 address")
            else:
                self.remote_gw = remote_gw
        else:
            if self.p1_type == 'dynamic':
                self.remote_gw = None
            else:
                raise Exception("\"remote_gw\" not set, static tunnel types require a remote gateway")

    def set_psk(self, psk):
        print("*** {} ***".format(psk))
        if psk:
            if isinstance(psk, str):
                if 6 <= len(psk) <= 30:
                    self.psk = psk
                else:
                    raise Exception("\"psk\", must be an str between 6 and 30 chars")
            else:
                raise Exception("\"psk\", must be a string")
        else:
            raise Exception("\"psk\" is required but was not provided")

    def set_local_id(self, local_id):
        if local_id:
            if isinstance(local_id, str):
                if 1 <= len(local_id) <= 63:
                    self.local_id = local_id
                else:
                    raise Exception("\"local_id\", when set, must be type str between 1 and 63 chars")
            else:
                raise Exception("\"local_id\", when set, must be type str")
        else:
            self.local_id = None

    def set_comment(self, comment):
        if comment:
            if isinstance(comment, str):
                if 1 <= len(comment) <= 1023:
                    self.comment = comment
                else:
                    raise Exception("\"description\", when set, must be type str between 1 and 1,023 chars")
            else:
                raise Exception("\"description\", when set, must be type str")
        else:
            self.comment = None

    def set_keepalive(self, keepalive):
        if keepalive:
            if isinstance(keepalive, int):
                if 10 <= keepalive <= 900:
                    self.keepalive = keepalive
                else:
                    raise Exception("\"keepalive\", when set, must be type int between 10 and 900")
            else:
                raise Exception("\"keepalive\", when set, must be type int")
        else:
            self.keepalive = None

    def set_add_route(self, add_route):
        if isinstance(add_route, bool):
            self.add_route = 'enable' if add_route else 'disable'
        else:
            self.add_route = None

    def set_add_gw_route(self, add_gw_route):
        if isinstance(add_gw_route, bool):
            self.add_gw_route = 'enable' if add_gw_route else 'disable'
        else:
            self.add_gw_route = None

    def set_net_device(self, net_device):
        if isinstance(net_device, bool):
            self.net_device = 'enable' if net_device else 'disable'
        else:
            self.net_device = None

    def set_tunnel_search(self, tunnel_search):
        if isinstance(tunnel_search, str):
            if tunnel_search.lower() == 'selectors':
                self.tunnel_search = 'selectors'
            elif tunnel_search.lower() == 'nexthop':
                self.tunnel_search = 'nexthop'
            else:
                raise Exception("\"tunnel_search\" was specified but is not value \"selectors\" or "
                                "\"nexthop\" as requried")
        else:
            self.tunnel_search = None

    def set_dpd(self, dpd):
        if isinstance(dpd, str):
            if dpd.lower() == 'disable':
                self.dpd = 'disable'
            elif dpd.lower() == 'on-idle':
                self.dpd = 'on-idle'
            elif dpd.lower == 'on-demand':
                self.dpd = 'on-demand'
            else:
                raise Exception("\"dpd\" was specied but is not value \"disable\", \"on-idle\" or \"on-demmand\""
                                "as required")
        else:
            self.dpd = None

    def set_nat_traversal(self, nat_traversal):
        if isinstance(nat_traversal, str):
            if nat_traversal.lower() == 'enable':
                self.nat_traversal = 'enable'
            elif nat_traversal.lower() == 'disable':
                self.nat_traversal = 'disable'
            elif nat_traversal.lower() == 'forced':
                self.nat_traversal = 'forced'
            else:
                raise Exception("\"nat_traversal\" when set, must be a string value of \"enable\", "
                                "\"disable\" or \"forced\"")
        else:
            self.nat_traversal = None

    def set_exchange_interface_ip(self, exchange_interface_ip):
        if isinstance(exchange_interface_ip, bool):
            self.exchange_interface_ip = 'enable' if exchange_interface_ip else 'disable'
        else:
            self.exchange_interface_ip = None

