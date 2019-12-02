import ipaddress
from typing import Union

from fgobjlib import FgObject


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

    def __init__(self, name: str = None, p1_type: str = None, interface: str = None, proposal: Union[str, list] = None,
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

        # Set parent class attributes #
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'name': 'name', 'p1_type': 'type', 'interface': 'interface', 'proposal': 'proposal',
                            'ike_version': 'ike-version', 'local_gw': 'local-gw', 'psksecret': 'psksecret',
                            'localid': 'localid', 'remote_gw': 'remote-gw', 'comment': 'comments',
                            'add_route': 'add-route', 'add_gw_route': 'add-gw-route', 'keepalive': 'keepalive',
                            'net_device': 'net-device', 'tunnel_search': 'tunnel-search', 'dpd': 'dpd',
                            'dhgrp': 'dhgrp', 'nattraversal': 'nattraversal',
                            'exchange_interface_ip': 'exchange-interface-ip'}

        self._cli_ignore_attrs = ['name']

        # Set instance attributes #
        self.name = name
        self.p1_type = p1_type
        self.interface = interface
        self.proposal = proposal
        self.ike_version = ike_version
        self.local_gw = local_gw
        self.psksecret = psksecret
        self.localid = localid
        self.remote_gw = remote_gw
        self.comment = comment
        self.add_route = add_route
        self.keepalive = keepalive
        self.add_gw_route = add_gw_route
        self.net_device = net_device
        self.tunnel_search = tunnel_search
        self.dpd = dpd
        self.dhgrp = dhgrp
        self.nattraversal = nattraversal
        self.exchange_interface_ip = exchange_interface_ip

        # Set object to string config
        self._obj_to_str += f', name={name}, p1_type={p1_type}, interface={self.interface}, ' \
                            f'proposal={self.proposal}, ike_version={self.ike_version}, local_gw={self.local_gw}, ' \
                            f'psksecret={self.psksecret}, localid={self.localid}, remote_gw={self.remote_gw}, ' \
                            f'comment={self.comment}, add_route={self.add_route}, add_gw_route={self.add_gw_route}, ' \
                            f'keepalive={self.keepalive}, net_device={self.net_device}, ' \
                            f'tunnel_search={self.tunnel_search}, dpd={self.dpd}, dhgrp={self.dhgrp},' \
                            f'nattraversal={self.nattraversal}, exchange_interface_ip={self.exchange_interface_ip}'

    # Instance properties and setters
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        """ Set self.name to name if name is valid

        Args:
            name: Name of object

        Returns:
            None
        """
        if name is None:
            self._name = None

        else:
            if name.isspace():
                raise Exception("'name', cannot be an empty string")
            if isinstance(name, str):
                if len(name) <= 35:
                    self._name = name
                else:
                    raise Exception("'name', must be type str() between 1 and 35 chars")
            else:
                raise Exception("'name', must be type str()")

    @property
    def proposal(self):
        return self._proposal

    @proposal.setter
    def proposal(self, proposal):
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
            self._proposal = None

        else:
            proposal_items = ''

            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list
            if isinstance(proposal, str):

                # compare proposal to valid_proposals list
                if proposal in valid_proposals:
                    proposal_items += f"{proposal} "
                else:
                    raise ValueError("'proposal' provided is not a valid FortiGate phase1 proposal option")

            elif isinstance(proposal, list):
                for item in proposal:
                    if isinstance(item, str):

                        # compare proposal to valid proposals list
                        if item in valid_proposals:
                            proposal_items += f"{item} "
                        else:
                            raise ValueError("'proposal'(s) provided contain at least one that is not a valid "
                                             "FortiGate phase1 proposal option")
            else:
                raise ValueError("'proposal' must be type str() or list() of str()")

            self._proposal = proposal_items

    @property
    def dhgrp(self):
        return self._dhgrp

    @dhgrp.setter
    def dhgrp(self, dhgrp):
        """ Set self.dhgrp to dhgrp if dhgrp is valid ForitGate dhgrp

        The dhgrp may be passed in as a str, or a list.  If the dhgrp(s) passed in are valid, add each
        of those to a space separated values string and set in self.dhgrp

        Args:
            dhgrp (list): single int representing one dhgrp or a list of ints for one or more dhgrps

        Returns:
            None
        """
        if dhgrp is None:
            self._dhgrp = None

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
                    raise ValueError("'dhgrp' provided is not a valid fortigate dhgrp option")

            elif isinstance(dhgrp, list):
                for item in dhgrp:
                    if isinstance(item, int):

                        # compare proposal to valid proposals list
                        if item in valid_dhgrps:
                            dhgrp_items += "{} ".format(item)
                        else:
                            raise ValueError(f"At least one 'dhgrp' provided is not a valid fortigate dhgrp option")
            else:
                raise ValueError("dhgrp must be type int()")

            self._dhgrp = dhgrp_items

    @property
    def p1_type(self):
        return self._p1_type

    @p1_type.setter
    def p1_type(self, p1_type):
        """ Set self.pt_type to p1_type if p1_type is valid

        Args:
            p1_type (str): Phase1-interface type.  ('dynamic', 'static', 'ddns' or None=inherit)

        Returns:

        """
        if p1_type is None:
            self._p1_type = None
        else:
            if isinstance(p1_type, str):
                if p1_type.lower() == 'dynamic':
                    self._p1_type = 'dynamic'
                elif p1_type.lower() == 'static':
                    self._p1_type = 'static'
                elif p1_type.lower() == 'ddns':
                    raise ValueError("p1_type of 'ddns' is not yet supported")
                else:
                    raise ValueError("'p1_type', must be type str() with value 'dynamic' or 'static'")
            else:
                raise ValueError("'p1_type', must be type str() with value of 'dynamic' or 'static'")

    @property
    def interface(self):
        return self._interface

    @interface.setter
    def interface(self, interface):
        """ set self.local_intfs to intf if intfs is valid

        Args:
            interface (str): Local interface for p1 attachment  (1 to 35 chars)

        Returns:
            None
        """
        if interface is None:
            self._interface = None

        else:
            if interface.isspace():
                raise ValueError("'interface', cannot be an empty string")
            if isinstance(interface, str):
                if len(interface) < 35:
                    self._interface = interface
                else:
                    raise ValueError("'interface', when set, must be type str() between 1 and 35 chars")
            else:
                raise ValueError("'interface', when set, must be type str()")

    @property
    def ike_version(self):
        return self._ike_version

    @ike_version.setter
    def ike_version(self, ike_version):
        """ Set self.ike_version to 1 or 2 if ike_version = 1 or 2.  Otherwise raise Exception

        Args:
            ike_version (int): ike-version.  (1 or 2)

        Returns:
            None
        """
        if ike_version is None:
            self._ike_version = None
        else:
            if isinstance(ike_version, int):
                if ike_version == 1:
                    self._ike_version = 1
                elif ike_version == 2:
                    self._ike_version = 2
                else:
                    raise ValueError("'ike_version', must be type int() with value '1' or '2'")
            else:
                raise ValueError("'ike_version' must be type int() with value = '1' or '2'")

    @property
    def local_gw(self):
        return self._local_gw

    @local_gw.setter
    def local_gw(self, local_gw):
        """ Set self.local_gw to local_gw if local_gw is valid ipv4 address

        Args:
            local_gw (str): Local gateway.  (valid ipv4 address as str())

        Returns:
            None
        """
        if local_gw is None:
            self._local_gw = None
        else:
            try:
                self._local_gw = str(ipaddress.ip_address(local_gw))
            except ValueError:
                raise ValueError("'local_gw', when set, must type str() with value containing a valid ipv4 address")

    @property
    def remote_gw(self):
        return self._remote_gw

    @remote_gw.setter
    def remote_gw(self, remote_gw):
        """ Set self.remote_gw to remote_gw if remote_gw is valid ipv4 address

        Args:
            remote_gw (str): Address of remote vpn peer gateway.  (valid ipv4 address as str())

        Returns:
            None
        """
        if remote_gw is None:
            self._remote_gw = None
        else:
            try:
                self._remote_gw = str(ipaddress.ip_address(remote_gw))
            except ValueError:
                raise ValueError("'remote_gw', when set, must be type str() with value containing a valid ipv4 address")

    @property
    def psksecret(self):
        return self._psksecret

    @psksecret.setter
    def psksecret(self, psk):
        """ Set self.psk to psk if psk valid

        Args:
            psk (str): Phase1 psksecret.  (6 to 30 chars)

        Returns:
            None
        """
        if psk is None:
            self._psksecret = None
        else:
            if isinstance(psk, str):
                if 6 <= len(psk) <= 30:
                    self._psksecret = psk
                else:
                    raise ValueError("'psksecret', must be type str() between 6 and 30 chars")
            else:
                raise ValueError("'psksecret', must be type str()")

    @property
    def localid(self):
        return self._localid

    @localid.setter
    def localid(self, localid):
        """ Set self.local_id to local_id if local_id is valid

        Args:
            localid (str): Phase1 local id.  (up to 68 chars)

       Returns:
            None
        """
        if localid is None:
            self._localid = None
        else:
            if isinstance(localid, str):
                if 1 <= len(localid) <= 63:
                    self._localid = localid
                else:
                    raise ValueError("'localid', when set, must be type str() between 1 and 63 chars")
            else:
                raise ValueError("'localid', when set, must be type str()")

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, comment):
        """ Set self.comment to comment if comment is valid

        Args:
            comment (str): Phase1 comment.  (up to 1023 chars)

        Returns:
            None
        """
        if comment is None:
            self._comment = None
        else:
            if isinstance(comment, str):
                if 1 <= len(comment) <= 1023:
                    self._comment = comment
                else:
                    raise ValueError("'description', when set, must be type str() between 1 and 1,023 chars")
            else:
                raise Exception("'description', when set, must be type str()")

    @property
    def keepalive(self):
        return self._keepalive

    @keepalive.setter
    def keepalive(self, keepalive):
        """ Set self.keepalive if keepalive valid

        Args:
            keepalive (int): phase1 keepalive  (10-900)

        Returns:
            None
        """
        if keepalive is None:
            self._keepalive = None
        else:
            if isinstance(keepalive, int):
                if 10 <= keepalive <= 900:
                    self._keepalive = keepalive
                else:
                    raise ValueError("'keepalive', when set, must be type int() between 10 and 900")
            else:
                raise ValueError("'keepalive', when set, must be type int()")

    @property
    def add_route(self):
        return self._add_route

    @add_route.setter
    def add_route(self, add_route):
        """ Set self.add_route

        Args:
            add_route (str): add-route.  ('enable', 'disable' or None=inherit)

        Returns:

        """
        if add_route is None:
            self._add_route = None
        else:
            if isinstance(add_route, str):
                if add_route == 'enable':
                    self._add_route = 'enable'
                elif add_route == 'disable':
                    self._add_route = 'disable'
                else:
                    raise ValueError("'add_route', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'add_route', when set, must be type str()")

    @property
    def add_gw_route(self):
        return self._add_gw_route

    @add_gw_route.setter
    def add_gw_route(self, add_gw_route):
        """ Set self.add_gw_route

        Args:
            add_gw_route (str): add-gw-route. ('enable', 'disable' or None=inherit)

        Returns:
            None
        """
        if add_gw_route is None:
            self._add_gw_route = None
        else:
            if isinstance(add_gw_route, str):
                if add_gw_route == 'enable':
                    self._add_gw_route = 'enable'
                elif add_gw_route == 'disable':
                    self._add_gw_route = 'disable'
                else:
                    raise ValueError("'add_gw_route', when set, must be type str() with value 'enable' or 'disable")
            else:
                raise ValueError("'add_gw_route', when set, must be type str()")

    @property
    def net_device(self):
        return self._net_device

    @net_device.setter
    def net_device(self, net_device):
        """ set self.net_device

        Args:
            net_device (str): net-device. ('enable', 'disable' or None=inherit)

        Returns:
            None
        """
        if net_device is None:
            self._net_device = None
        else:
            if isinstance(net_device, str):
                if net_device == 'enable':
                    self._net_device = 'enable'
                elif net_device == 'disable':
                    self._net_device = 'disable'
                else:
                    raise ValueError("'net_device', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'net_device', when set, must be type str()")

    @property
    def tunnel_search(self):
        return self._tunnel_search

    @tunnel_search.setter
    def tunnel_search(self, tunnel_search):
        """ Set self.tunnel_search

        Args:
            tunnel_search (str): tunnel-search.  ('selectors', 'nexthop', None=inherit)

        Returns:
            None
        """
        if tunnel_search is None:
            self._tunnel_search = None
        else:
            if isinstance(tunnel_search, str):
                if tunnel_search.lower() == 'selectors':
                    self._tunnel_search = 'selectors'
                elif tunnel_search.lower() == 'nexthop':
                    self._tunnel_search = 'nexthop'
                else:
                    raise Exception("'tunnel_search' when set, must be type str() with value 'selectors', 'nexthop'")
            else:
                raise ValueError("'tunnel_search', when set, must be type str(0")

    @property
    def dpd(self):
        return self._dpd

    @dpd.setter
    def dpd(self, dpd):
        """ Set self.dpd

        Args:
            dpd (str): phase1 dpd.   ('disable', 'on-idle', 'on-demand', None=inherit)

        Returns:
            None
        """
        if dpd is None:
            self._dpd = None
        else:
            if isinstance(dpd, str):
                if dpd.lower() == 'disable':
                    self._dpd = 'disable'
                elif dpd.lower() == 'on-idle':
                    self._dpd = 'on-idle'
                elif dpd.lower == 'on-demand':
                    self._dpd = 'on-demand'
                else:
                    raise Exception("'dpd', when set, must be type str() with value 'disable', 'on-idle' or "
                                    "'on-demmand")
            else:
                raise ValueError("'dpd', when set, must be type str()")

    @property
    def nattraversal(self):
        return self._nattraversal

    @nattraversal.setter
    def nattraversal(self, nattraversal):
        """ Set self.nat_traversal

        Args:
            nattraversal (str): nat-traversal.  ('enable', 'disable', 'forced', None=inherit)

        Returns:
            None
        """
        if nattraversal is None:
            self._nattraversal = None
        else:
            if isinstance(nattraversal, str):
                if nattraversal.lower() == 'enable':
                    self._nattraversal = 'enable'
                elif nattraversal.lower() == 'disable':
                    self._nattraversal = 'disable'
                elif nattraversal.lower() == 'forced':
                    self._nattraversal = 'forced'
                else:
                    raise ValueError("'nattraversal', when set, must be type str() with value 'enable', 'disable' "
                                     "or 'forced'")
            else:
                raise ValueError("'nattraversal', when set, must be type str()")

    @property
    def exchange_interface_ip(self):
        return self._exchange_interface_ip

    @exchange_interface_ip.setter
    def exchange_interface_ip(self, exchange_interface_ip):
        """ Set self.exchange_interface_ip

        Args:
            exchange_interface_ip (str): exchange-interface-ip. ('enable', 'disable' or None)

        Returns:
            None
        """
        if exchange_interface_ip is None:
            self._exchange_interface_ip = None
        else:
            if isinstance(exchange_interface_ip, str):
                if exchange_interface_ip == 'enable':
                    self._exchange_interface_ip = 'enable'
                elif exchange_interface_ip == 'disable':
                    self._exchange_interface_ip = 'disable'
                else:
                    raise ValueError("exchange_interface_ip, when set, must be type str() with value 'enable' or "
                                     "'disable")
            else:
                raise ValueError("exchange_interface_ip, when set, must be type str()")
