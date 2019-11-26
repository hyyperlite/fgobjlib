from fgobjlib import FgObject
import ipaddress

class FgIpsecP1Interface(FgObject):
    """ FgIpsecP1Interface class represents FortiGate Firewall ipsec phase1 interface object and provides methods for
    validating parameters and generating both cli and api configuration data for use in external configuration
    applications

    Currently supports dynamic or static VPN using psk authentication. No support yet for advpn or mode-cfg

    Attributes:
        name (str): Name of ipsec phase1-interface object
        p1_type (str): Phase1-interface type
        interface (str): Name of locally attached fortigate interface
        proposal (list): Phase1-interface proposal(s)
        ike_version (int): ike version
        local_gw (str): Phase1-interface local-gw IP
        psksecret (str): Pre-shared key
        localid (str): Local ID
        remote_gw (str): Remote Gateway
        add_route (str):  add-route ('enable', 'disable', or None=inherit)
        add_gw_route (str): add-gw-route ('enable', 'disable', or None=inherit)
        keepalive (int): Keepalive in seconds
        net_device (str): net-device  ('enable', 'disable', or None=inherit)
        comment (str): phase1 comment
        vdom (str): Associated VDOM, if applicable
        tunnel_search (str):  tunnel-search ('next-hop', 'selectors' or None=inherit)
        dpd (str): phase1 DPD ('on-demand', 'on-idle', 'disable' or None=inherit)
        dhgrp (str): dhgrp
        nattraversal (str): nattraversal ('enable', 'disable', 'forced' or None=inherit)
        exchange_interface_ip (str): exchange-interface-ip ('enable', 'disable', or None=inherit)
    """

    def __init__(self, name: str = None, p1_type: str = None, interface: str = None, proposal: list = None,
                 ike_version: int = None, local_gw: str = None, psksecret: str = None, localid: str = None,
                 remote_gw: str = None, add_route: str = None, add_gw_route: str = None, keepalive: int = None,
                 net_device: str = None, comment: str = None, vdom: str = None, tunnel_search: str = None,
                 dpd: str = None, dhgrp: list = None, nattraversal: str = None, exchange_interface_ip: str = None):

        """
        Args:
            name (str): Set name of ipsec phase1-interface object
            p1_type (str): Set phase1-interface type
            interface (str): Set name of locally attached fortigate interface
            proposal (list): Set phase1-interface proposal(s)
            ike_version (int): Set ike version
            local_gw (str): Set phase1-interface local-gw IP
            psksecret (str): Set pre-shared key
            localid (str): Set local ID
            remote_gw (str): Set remote Gateway
            add_route (str):  Set add-route ('enable', 'disable', or None=inherit)
            add_gw_route (str): Set add-gw-route ('enable', 'disable', or None=inherit)
            keepalive (int): Set keepalive in seconds
            net_device (str): Set net-device ('enable', 'disable', or None=inherit)
            comment (str): Set phase1 comment
            vdom (str): Set associated VDOM, if applicable
            tunnel_search (str):  Set tunnel-search ('next-hop', 'selectors' or None=inherit)
            dpd (list): Set phase1 DPD ('on-demand', 'on-idle', 'disable' or None=inherit)
            nattraversal (str): Set nattraversal ('enable', 'disable', 'forced' or None=inherit)
            exchange_interface_ip (str): Set exchange-interfce-ip ('enable', 'disable', or None=inherit)
        """

        # Initialize the parent class
        super().__init__(api='cmdb', api_path='vpn.ipsec', api_name='phase1-interface',
                         cli_path="config vpn ipsec phase1-interface", obj_id=name, vdom=vdom)

        ### Set parent class attributes ###
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'name': 'name', 'p1_type': 'type', 'interface': 'interface', 'proposal': 'proposal',
                           'ike_version': 'ike-version', 'local_gw': 'local-gw', 'psksecret': 'psksecret',
                           'localid': 'localid', 'remote_gw': 'remote-gw', 'comment': 'comments',
                           'add_route': 'add-route', 'add_gw_route': 'add-gw-route', 'keepalive': 'keepalive',
                           'net_device': 'net-device', 'tunnel_search': 'tunnel-search', 'dpd': 'dpd', 'dhgrp': 'dhgrp',
                           'nattraversal': 'nattraversal', 'exchange_interface_ip': 'exchange-interface-ip'}

        self._cli_ignore_attrs = ['name']

        # Set instance attributes
        self.set_name(name)
        self.set_p1_type(p1_type)
        self.set_interface(interface)
        self.set_proposal(proposal)
        self.set_ike_version(ike_version)
        self.set_local_gw(local_gw)
        self.set_psksecret(psksecret)
        self.set_localid(localid)
        self.set_remote_gw(remote_gw)
        self.set_comment(comment)
        self.set_add_route(add_route)
        self.set_keepalive(keepalive)
        self.set_add_gw_route(add_gw_route)
        self.set_net_device(net_device)
        self.set_tunnel_search(tunnel_search)
        self.set_dpd(dpd)
        self.set_dhgrp(dhgrp)
        self.set_nattraversal(nattraversal)
        self.set_exchange_interface_ip(exchange_interface_ip)

        self._obj_to_str += f', name={name}, p1_type={p1_type}, interface={self.interface}, ' \
                          f'proposal={self.proposal}, ike_version={self.ike_version}, local_gw={self.local_gw}, ' \
                          f'psksecret={self.psksecret}, localid={self.localid}, remote_gw={self.remote_gw}, ' \
                          f'comment={self.comment}, add_route={self.add_route}, add_gw_route={self.add_gw_route}, ' \
                          f'keepalive={self.keepalive}, net_device={self.net_device}, ' \
                          f'tunnel_search={self.tunnel_search}, dpd={self.dpd}, dhgrp={self.dhgrp},' \
                          f'nattraversal={self.nattraversal}, exchange_interface_ip={self.exchange_interface_ip}'


    # Instance Methods
    def set_name(self, name):
        """ Set self.name to name if name is valid

        Args:
            name: Name of object

        Returns:
            None
        """
        if name is None:
            self.name = None

        else:
            if name.isspace(): raise Exception("'name', cannot be an empty string")
            if isinstance(name, str):
                if len(name) <= 35:
                    self.name = name
                else:
                    raise Exception("'name', must be less than 35 chars or less")
            else:
                raise Exception("'name', must be a string")

    def set_proposal(self, proposal):
        """ Set self.proposal with list of proposals from proposal if items are all acceptable FG proposals

        Args:
            proposal (list): string containing a single p1 proposal or list of strings with one or more p1 propolsals

        Returns:
            None
        """
        valid_proposals = ['des-md5', 'des-sha', 'des-sha256', 'des-sha384', 'des-sha512', '3des-md5', '3des-sha1',
                           '3des-sha256', '3des-sha384', '3des-sha512', 'aes128-md5', 'aes128-sha1', 'aes128-sha256',
                           'aes128-sha384', 'aes128-sha512', 'aes192-md5', 'aes192-sha1', 'aes192-sha256',
                           'aes192-sha384', 'aes192-sha512', 'aes256-md5', 'aes256-sha1', 'aes256-sha256',
                           'aes256-sha384', 'aes256-sha512', 'aria128-md5', 'aria128-sha1', 'aria128-sha256',
                           'aria128-sha384', 'aria128-sha512', 'aria192-md5', 'aria192-sha1', 'aria192-sha256',
                           'aria192-sha384', 'aria192-sha512', 'aria256-md5', 'aria256-sha1', 'aria256-sha256',
                           'aria256-sha384', 'aria256-sha512', 'seed-md5', 'seed-sha1', 'seed-sha256', 'seed-sha384',
                           'seed-sha512']

        if proposal is None:
            self.proposal = None

        else:
            proposal_items = ''

            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list
            if isinstance(proposal, str):

                # compare proposal to valid_proposals list
                if proposal in valid_proposals:
                    proposal_items += f"{proposal} "
                else:
                    raise ValueError(f"'proposal' provided: {proposal} is not a valid FortiGate phase1 proposal")

            elif isinstance(proposal, list):
                for item in proposal:
                    if isinstance(item, str):

                        # compare proposal to valid proposals list
                        if item in valid_proposals:
                            proposal_items += f"{item} "
                        else:
                            raise ValueError("'proposal' provided: {proposal} is not a valid FortiGate phase1 proposal")
            else:
                raise ValueError("proposal must be provided as type string (with single proposal referenced or as a "
                                 "list for multiple proposal references")

            self.proposal = proposal_items

    def set_dhgrp(self, dhgrp):
        """ Set self.dhgrp to dhgrp if dhgrp is valid ForitGate dhgrp

        The dhgrp may be passed in as a str, or a list.  If the dhgrp(s) passed in are valid, add each
        of those to a space separated values string and set in self.dhgrp

        Args:
            dhgrp (list): single int representing one dhgrp or a list of ints for one or more dhgrps

        Returns:
            None
        """
        if dhgrp is None:
            self.dhgrp = None

        else:
            dhgrp_items = ''
            valid_dhgrps = [1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 30, 31, 32]

            # IF a single object was passed as a string, append it to list else iterate the list and pull
            # out the dhgrps and add to list to be set as self object
            if isinstance(dhgrp, int):
                # compare proposal to valid_list
                if dhgrp in valid_dhgrps:
                    dhgrp_items += "{} ".format(dhgrp)
                else:
                    raise ValueError(f"'dhgrp' provided: {dhgrp}, is not a valid fortigate dhgrp")

            elif isinstance(dhgrp, list):
                for item in dhgrp:
                    if isinstance(item, int):

                        # compare proposal to valid proposals list
                        if item in valid_dhgrps:
                            dhgrp_items += "{} ".format(item)
                        else:
                            raise ValueError(f"At least one 'dhgrp' provided: {dhgrp} is not a valid fortigate phase1 "
                                             "proposal option")
            else:
                raise ValueError("dhgrp must be provided as type integer")

            self.dhgrp = dhgrp_items

    def set_p1_type(self, p1_type):
        """ Set self.pt_type to p1_type if p1_type is valid

        Args:
            p1_type (str): Phase1-interface type.  ('dynamic', 'static', 'ddns' or None=inherit)

        Returns:

        """
        if p1_type is None:
            self.p1_type = None
        else:
            if isinstance(p1_type, str):
                if p1_type.lower() == 'dynamic':
                    self.p1_type = 'dynamic'
                elif p1_type.lower() == 'static':
                    self.p1_type = 'static'
                elif p1_type.lower() == 'ddns':
                    raise ValueError("p1_type of 'ddns' is not yet supported")
                else:
                    raise ValueError(f"'p1_type': {p1_type} is not supported")
            else:
                raise ValueError("'p1_type', when set, must be a str with value of 'dynamic' or 'static'")

    def set_interface(self, interface):
        """ set self.local_intfs to intf if intfs is valid

        Args:
            interface (str): Local interface for p1 attachment  (1 to 35 chars)

        Returns:
            None
        """
        if interface is None:
            self.interface = None

        else:
            if interface.isspace(): raise ValueError("'interface', cannot be an empty string")
            if isinstance(interface, str):
                if len(interface) < 35:
                    self.interface = interface
                else:
                    raise ValueError("'interface', when set, must be less than 35 chars or less")
            else:
                raise ValueError("'interface', when set, must be a string")

    def set_ike_version(self, ike_version):
        """ Set self.ike_version to 1 or 2 if ike_version = 1 or 2.  Otherwise raise Exception

        Args:
            ike_version (int): ike-version.  (1 or 2)

        Returns:
            None
        """
        if ike_version is None:
            self.ike_version = None
        else:
            if isinstance(ike_version, int):
                if ike_version == 1:
                    self.ike_version = 1
                elif ike_version == 2:
                    self.ike_version = 2
                else:
                    raise ValueError("'ike_version', when set must be type int with value = '1' or '2'")
            else:
                raise ValueError("'ike_version' when set, must be type int with value = '1' or '2'")

    def set_local_gw(self, local_gw):
        """ Set self.local_gw to local_gw if local_gw is valid ipv4 address

        Args:
            local_gw (str): Local gateway.  (valid ipv4 address as str())

        Returns:
            None
        """
        if local_gw is None:
            self.local_gw = None
        else:
            try:
                self.local_gw = str(ipaddress.ip_address(local_gw))
            except ValueError:
                raise ValueError("'local_gw', when set, must type str() with value containing a valid ipv4 address")


    def set_remote_gw(self, remote_gw):
        """ Set self.remote_gw to remote_gw if remote_gw is valid ipv4 address

        Args:
            remote_gw (str): Address of remote vpn peer gateway.  (valid ipv4 address as str())

        Returns:
            None
        """
        if remote_gw is None:
            self.remote_gw = None
        else:
            try:
                self.remote_gw = str(ipaddress.ip_address(remote_gw))
            except ValueError:
                raise ValueError("'remote_gw', when set, must be type str() with value containing a valid ipv4 address")


    def set_psksecret(self, psk):
        """ Set self.psk to psk if psk valid

        Args:
            psk (str): Phase1 psksecret.  (6 to 30 chars)

        Returns:
            None
        """
        if psk is None:
            self.psksecret = None
        else:
            if isinstance(psk, str):
                if 6 <= len(psk) <= 30:
                    self.psksecret = psk
                else:
                    raise ValueError("'psksecret', must be type str() between 6 and 30 chars")
            else:
                raise ValueError("'psksecret', must be type str()")

    def set_localid(self, localid):
        """ Set self.local_id to local_id if local_id is valid

        Args:
            localid (str): Phase1 local id.  (up to 68 chars)

       Returns:
            None
        """
        if localid is None:
            self.localid = None
        else:
            if isinstance(localid, str):
                if 1 <= len(localid) <= 63:
                    self.localid = localid
                else:
                    raise ValueError("'localid', when set, must be type str() between 1 and 63 chars")
            else:
                raise ValueError("'localid', when set, must be type str()")

    def set_comment(self, comment):
        """ Set self.comment to comment if comment is valid

        Args:
            comment (str): Phase1 comment.  (up to 1023 chars)

        Returns:
            None
        """
        if comment is None:
            self.comment = None
        else:
            if isinstance(comment, str):
                if 1 <= len(comment) <= 1023:
                    self.comment = comment
                else:
                    raise ValueError("'description', when set, must be type str() between 1 and 1,023 chars")
            else:
                raise Exception("'description', when set, must be type str()")

    def set_keepalive(self, keepalive):
        """ Set self.keepalive if keepalive valid

        Args:
            keepalive (int): phase1 keepalive  (10-900)

        Returns:
            None
        """
        if keepalive is None:
            self.keepalive = None
        else:
            if isinstance(keepalive, int):
                if 10 <= keepalive <= 900:
                    self.keepalive = keepalive
                else:
                    raise ValueError("'keepalive', when set, must be type int() between 10 and 900")
            else:
                raise ValueError("'keepalive', when set, must be type int()")

    def set_add_route(self, add_route):
        """ Set self.add_route

        Args:
            add_route (str): add-route.  ('enable', 'disable' or None=inherit)

        Returns:

        """
        if add_route is None:
            self.add_route = None
        else:
            if isinstance(add_route, str):
                if add_route == 'enable':
                    self.add_route = 'enable'
                elif add_route == 'disable':
                    self.add_route = 'disable'
                else:
                    raise ValueError("'add_route', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'add_route', when set, must be type str()")

    def set_add_gw_route(self, add_gw_route):
        """ Set self.add_gw_route

        Args:
            add_gw_route (str): add-gw-route. ('enable', 'disable' or None=inherit)

        Returns:
            None
        """
        if add_gw_route is None:
            self.add_gw_route = None
        else:
            if isinstance(add_gw_route, str):
                if add_gw_route == 'enable':
                    self.add_gw_route = 'enable'
                elif add_gw_route == 'disable':
                    self.add_gw_route = 'disable'
                else:
                    raise ValueError("'add_gw_route', when set, must be type str() with value 'enable' or 'disable")
            else:
                raise ValueError("'add_gw_route', when set, must be type str()")

    def set_net_device(self, net_device):
        """ set self.net_device

        Args:
            net_device (str): net-device. ('enable', 'disable' or None=inherit)

        Returns:
            None
        """
        if net_device is None:
            self.net_device = None
        else:
            if isinstance(net_device, str):
                if net_device == 'enable':
                    self.net_device = 'enable'
                elif net_device == 'disable':
                    self.net_device = 'disable'
                else:
                    raise ValueError("'net_device', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'net_device', when set, must be type str()")

    def set_tunnel_search(self, tunnel_search):
        """ Set self.tunnel_search

        Args:
            tunnel_search (str): tunnel-search.  ('selectors', 'nexthop', None=inherit)

        Returns:
            None
        """
        if tunnel_search is None:
            self.tunnel_search = None
        else:
            if isinstance(tunnel_search, str):
                if tunnel_search.lower() == 'selectors':
                    self.tunnel_search = 'selectors'
                elif tunnel_search.lower() == 'nexthop':
                    self.tunnel_search = 'nexthop'
                else:
                    raise Exception("'tunnel_search' when set, must be type str() with value 'selectors', 'nexthop'")
            else:
                raise ValueError("'tunnel_search', when set, must be type str(0")

    def set_dpd(self, dpd):
        """ Set self.dpd

        Args:
            dpd (str): phase1 dpd.   ('disable', 'on-idle', 'on-demand', None=inherit)

        Returns:
            None
        """
        if dpd is None:
            self.dpd = None
        else:
            if isinstance(dpd, str):
                if dpd.lower() == 'disable':
                    self.dpd = 'disable'
                elif dpd.lower() == 'on-idle':
                    self.dpd = 'on-idle'
                elif dpd.lower == 'on-demand':
                    self.dpd = 'on-demand'
                else:
                    raise Exception("'dpd', when set, must be type str() with value 'disable', 'on-idle' or "
                                    "'on-demmand")
            else:
                raise ValueError("'dpd', when set, must be type str()")

    def set_nattraversal(self, nattraversal):
        """ Set self.nat_traversal

        Args:
            nattraversal (str): nat-traversal.  ('enable', 'disable', 'forced', None=inherit)

        Returns:
            None
        """
        if nattraversal is None:
            self.nattraversal = None
        else:
            if isinstance(nattraversal, str):
                if nattraversal.lower() == 'enable':
                    self.nattraversal = 'enable'
                elif nattraversal.lower() == 'disable':
                    self.nattraversal = 'disable'
                elif nattraversal.lower() == 'forced':
                    self.nattraversal = 'forced'
                else:
                    raise ValueError("'nattraversal', when set, must be type str() with value 'enable', 'disable' "
                                    "or 'forced'")
            else:
                raise ValueError("'nattraversal', when set, must be type str()")

    def set_exchange_interface_ip(self, exchange_interface_ip):
        """ Set self.exchange_interface_ip

        Args:
            exchange_interface_ip (str): exchange-interface-ip. ('enable', 'disable' or None)

        Returns:
            None
        """
        if exchange_interface_ip is None:
            self.exchange_interface_ip = None
        else:
            if isinstance(exchange_interface_ip, str):
                if exchange_interface_ip == 'enable':
                    self.exchange_interface_ip = 'enable'
                elif exchange_interface_ip == 'disable':
                    self.exchange_interface_ip = 'disable'
                else:
                    raise ValueError("exchange_interface_ip, when set, must be type str() with value 'enable' or "
                                     "'disable")
            else:
                raise ValueError("exchange_interface_ip, when set, must be type str()")
