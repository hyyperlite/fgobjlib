import ipaddress
from typing import Union

from fgobjlib import FgObject


class FgIpsecP2Interface(FgObject):
    """
    FgIpsecP2Interface class represents FortiGate Firewall ipsec phase2 interface object and provides methods for
    validating parameters and generating both cli and api configuration data for use in external configuration
    applications and ftntlib

    Currently supports dynamic or static VPN using psk authentication. No support yet for advpn or mode-cfg or pki

    Attributes:
        name (str): Name of phase2-interface
        phase1name (str): Name of phase1-interface to bind to
        proposal (str): phase2 proposal(s)
        pfs (str): perfect forward secrecy,  should be either 'enable' or 'disable'
        dhgrp (str): phase2 dhgrp(s)
        keepalive (str): keepalive, should be either 'enable' or 'disable'
        replay (str): replay protection
        comment (str): phase2 comment
        auto_negotiate (str): auto-negotiation, should be either 'enable' or 'disable'
        vdom (str): associated VDOM
        src_subnet (str):  source selector, for selectors type subnet
        dst_subnet (str): destination selector, for selectors type subnet
    """

    def __init__(self, name: str = None, phase1name: str = None, proposal: list = None, pfs: str = None,
                 dhgrp: Union[str, list] = None, keepalive: str = None, replay: str = None, comment: str = None,
                 auto_negotiate: str = None, vdom: str = None, src_subnet: str = None, dst_subnet: str = None):
        """
        Args:
            name (str): Name of phase2-interface
            phase1name (str): Name of phase1-interface to bind to
            proposal (str): phase2 proposal(s)
            pfs (str): perfect forward secrecy.  Allowed values are 'enable' or 'disable'
            dhgrp (str): phase2 dhgrp(s)
            keepalive (str): keepalive.  Allowed values are 'enable' or 'disable'
            replay (str): replay protection (True=enabled, False=disable, None=inherit)
            comment (str): phase2 comment
            auto_negotiate (str): Auto-negotiation. Allowed values are 'enable' or 'disable'
            vdom (str): associated VDOM
            src_subnet (str):  source selector, for selectors type subnet
            dst_subnet (str): destination selector, for selectors type subnet
        """

        # Initialize the parent class
        super().__init__(api='cmdb', api_path='vpn.ipsec', api_name='phase2-interface',
                         cli_path="config vpn ipsec phase2-interface", obj_id=name, vdom=vdom)

        # Set parent class attributes #
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'name': 'name', 'phase1name': 'phase1name', 'proposal': 'proposal',
                            'comment': 'comments', 'keepalive': 'keepalive', 'dhgrp': 'dhgrp', 'pfs': 'pfs',
                            'replay': 'replay', 'auto_negotiate': 'auto-negotiate', 'src_subnet': 'src-subnet',
                            'dst_subnet': 'dst-subnet'}

        self._cli_ignore_attrs = ['name']

        # Set instance attributes #
        self.name = name
        self.phase1name = phase1name
        self.proposal = proposal
        self.comment = comment
        self.keepalive = keepalive
        self.dhgrp = dhgrp
        self.pfs = pfs
        self.replay = replay
        self.auto_negotiate = auto_negotiate
        self.src_subnet = src_subnet
        self.dst_subnet = dst_subnet

        # Update the parent defined obj_to_str attribute with this objects str representation
        self._obj_to_str += f', name={self.name}, phase1name={self.phase1name}, proposal={self.proposal}, ' \
                            f'comment={self.comment}, keepalive={self.keepalive}, dhgrp={self.dhgrp}, ' \
                            f'pfs={self.pfs}, replay={self.replay}, auto_negotiate={self.auto_negotiate}, ' \
                            f'src_subnet={self.src_subnet}, dst_subnet={self.dst_subnet}'

    # Instance properties and setters
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        """ Set self.name to name if name valid

        Args:
            name (str): Name for phase2-interface

        Returns:
            None
        """
        if name is None:
            self._name = None
        else:
            if name.isspace():
                raise ValueError("'name', cannot be an empty")
            if isinstance(name, str):
                if len(name) <= 35:
                    self._name = name
                else:
                    raise ValueError("'name', must be type str() between 1 and 35 chars")
            else:
                raise ValueError("'name', must be type str()")

    @property
    def phase1name(self):
        return self._phase1name

    @phase1name.setter
    def phase1name(self, phase1name):
        """ Set self.phase1name to phase1name if phase1name valid

        Args:
            phase1name (str): phase1name to bind to

        Returns:
            None
        """
        if phase1name is None:
            self._phase1name = None
        else:
            if phase1name.isspace():
                raise ValueError("'phase1name', cannot be an empty string")
            if isinstance(phase1name, str):
                if len(phase1name) <= 35:
                    self._phase1name = phase1name
                else:
                    raise ValueError("'phase1name', must be type str between 1 and 35 chars")
            else:
                raise ValueError("'phase1name', must be type str()")

    @property
    def proposal(self):
        return self._proposal

    @proposal.setter
    def proposal(self, proposal):
        """ Set self.proposal to proposal if proposal contains valid FG proposals

        Args:
            proposal: phase2 proposal.  May be string or list of strings.  i.e. 'des-md5' or ['des-md5', '3des-md5']

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
                           'seed-sha512', 'chacha20poly1305', 'null-md5', 'null-sha1', 'null-sha256', 'null-sha384',
                           'null-sha512', 'des-null', '3des-null', 'aes128-null', 'aes192-null', 'aes256-null',
                           'aria128-null', 'seed-null']

        if proposal is None:
            self._proposal = None

        else:
            proposal_items = ''

            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list
            if isinstance(proposal, str):

                # compare proposal to valid_proposals list
                if proposal in valid_proposals:
                    proposal_items += f"{proposal}"
                else:
                    raise ValueError("'proposal' value provided is not a valid fortigate phase1 proposal option")

            elif isinstance(proposal, list):
                for item in proposal:
                    if isinstance(item, str):

                        # compare proposal to valid proposals list
                        if item in valid_proposals:
                            proposal_items += f" {item}"
                        else:
                            raise ValueError("'proposal' value provided not a valid fortigate phase1 proposal option")
            else:
                raise ValueError("'proposal' must be type str() with single proposal referenced or type list() for "
                                 "multiple proposal references")

            self._proposal = proposal_items

    @property
    def dhgrp(self):
        return self._dhgrp

    @dhgrp.setter
    def dhgrp(self, dhgrp):
        """  Set self.dhgrp to string containing values dhgrp if dhgrp contains valid FortiGate proposals

        The dhgrp may be passed in as a str, or a list.  If the dhgrp(s) passed in are valid we'll add each
        of those to a space separated values string and set in self.dhgrp

        Args:
            dhgrp (list): list of valid fortigate dhgrps

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
                    dhgrp_items += f"{dhgrp} "
                else:
                    raise ValueError(f"'dhgrp' value provided is not a valid fortigate dhgrp option")

            elif isinstance(dhgrp, list):
                for item in dhgrp:
                    if isinstance(item, int):

                        # compare proposal to valid proposals list
                        if item in valid_dhgrps:
                            dhgrp_items += f"{item} "
                        else:
                            raise ValueError(f"At least one 'dhgrp' provided is not a valid fortigate phase1 proposal")
            else:
                raise ValueError("dhgrp must be provided as type int() or list() of int()")

            self._dhgrp = dhgrp_items

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, comment):
        """ Set self.comment to comment if comment valid

        Args:
            comment (str): phase2-interface comment

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
                raise ValueError("'description', when set, must be type str()")

    @property
    def keepalive(self):
        return self._keepalive

    @keepalive.setter
    def keepalive(self, keepalive):
        """ Set self.keepalive to keepalive if keepalive valid

        Args:
            keepalive (str):  keepalive, allowed values: 'enable' or 'disable'

        Returns:
            None
        """
        if keepalive is None:
            self._keepalive = None
        else:
            if isinstance(keepalive, str):
                if keepalive == 'enable':
                    self._keepalive = 'enable'
                elif keepalive == 'disable':
                    self._keepalive = 'disable'
                else:
                    raise ValueError("'keepalive' when set must be type str() with value 'enable' or 'disable'")

            else:
                raise ValueError("'keepalive', when set, must be type str()")

    @property
    def pfs(self):
        return self._pfs

    @pfs.setter
    def pfs(self, pfs):
        """ set self.pfs to enable, disable or None based on pfs value

        Args:
            pfs (str): pfs, allowed values: 'enable'  or 'disable'

        Returns:
            None
        """
        if pfs is None:
            self._pfs = None
        else:
            if isinstance(pfs, str):
                if pfs == 'enable':
                    self._pfs = 'enable'
                elif pfs == 'disable':
                    self._pfs = 'disable'
                else:
                    raise ValueError("'pfs', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'pfs', when set, must be type str()")

    @property
    def replay(self):
        return self._replay

    @replay.setter
    def replay(self, replay):
        """ Set self.replay to enable, disable or None

        Args:
            replay (str): replay protection, allowed values: 'enable' or 'disable'

        Returns:
            None
        """
        if replay is None:
            self._replay = None
        else:
            if isinstance(replay, str):
                if replay == 'enable':
                    self._replay = 'enable'
                elif replay == 'disable':
                    self._replay = 'disable'
                else:
                    raise ValueError("'replay', when set must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'pfs', when set, must type str()")

    @property
    def auto_negotiate(self):
        return self.auto_negotiate

    @auto_negotiate.setter
    def auto_negotiate(self, auto_negotiate):
        """ Set self.auto_negotiate to enable, disable or None

        Args:
            auto_negotiate (str): auto-negotiation, allowed values: 'enable' or 'disable'

        Returns:
        None
        """
        if auto_negotiate is None:
            self._auto_negotiate = None
        else:
            if isinstance(auto_negotiate, str):
                if auto_negotiate == 'enable':
                    self._auto_negotiate = 'enable'
                elif auto_negotiate == 'disable':
                    self._auto_negotiate = 'disable'
                else:
                    raise ValueError("'auto_negotiate', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'pfs', when set, must type str()")

    @property
    def src_subnet(self):
        return self._src_subnet

    @src_subnet.setter
    def src_subnet(self, src_subnet):
        """ Set self.src_subnet if src_subnet valid

        Args:
            src_subnet: Source Selector when selector type set to subnet.  Must be valid ipv4 network/mask.

        Returns:
            None
        """
        if src_subnet is None:
            self._src_subnet = None
        else:
            try:
                ipaddress.ip_network(src_subnet)
            except ValueError:
                raise ValueError("'src_subnet', when set, must be a valid ipv4 or ipv6 address")
            else:
                self._src_subnet = src_subnet

    @property
    def dst_subnet(self):
        return self._dst_subnet

    @dst_subnet.setter
    def dst_subnet(self, dst_subnet):
        """ Set self.dst_subnet if dst_subnet valid

        Args:
            dst_subnet: Destination Selector when selector type set to subnet.  Must be valid ipv4 network/mask.

        Returns:
            None
        """
        if dst_subnet is None:
            self._dst_subnet = None
        else:
            try:
                ipaddress.ip_network(dst_subnet)
            except ValueError:
                raise ValueError("'dst_subnet', when set, must be type str() with value a valid ipv4 or ipv6 address")
            else:
                self._dst_subnet = dst_subnet
