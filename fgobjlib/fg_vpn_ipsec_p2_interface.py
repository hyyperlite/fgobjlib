from fgobjlib import FgObject
import ipaddress

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
                 dhgrp: list = None, keepalive: str = None, replay: str = None, comment: str = None,
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
        self.data_attrs = {'name': 'name', 'phase1name': 'phase1name', 'proposal': 'proposal',
                           'comment': 'comments', 'keepalive': 'keepalive', 'dhgrp': 'dhgrp', 'pfs': 'pfs',
                           'replay': 'replay', 'auto_negotiate': 'auto-negotiate', 'src_subnet': 'src-subnet',
                           'dst_subnet': 'dst-subnet'}

        self.cli_ignore_attrs = ['name']

        # Set instance attributes #
        self.set_name(name)
        self.set_phase1name(phase1name)
        self.set_proposal(proposal)
        self.set_comment(comment)
        self.set_keepalive(keepalive)
        self.set_dhgrp(dhgrp)
        self.set_pfs(pfs)
        self.set_replay(replay)
        self.set_auto_negotiate(auto_negotiate)
        self.set_src_subnet(src_subnet)
        self.set_dst_subnet(dst_subnet)

        # Update the parent defined obj_to_str attribute with this objects str representation
        self.obj_to_str += f', name={self.name}, phase1name={self.phase1name}, proposal={self.proposal}, ' \
                           f'comment={self.comment}, keepalive={self.keepalive}, dhgrp={self.dhgrp}, pfs={self.pfs}, ' \
                           f'replay={self.replay}, auto_negotiate={self.auto_negotiate}, ' \
                           f'src_subnet={self.src_subnet}, dst_subnet={self.dst_subnet}'


    def set_name(self, name):
        """ Set self.name to name if name valid

        Args:
            name (str): Name for phase2-interface

        Returns:
            None
        """
        if name is None:
            self.name = None

        else:
            if name.isspace(): raise ValueError("'name', cannot be an empty string")
            if isinstance(name, str):
                if len(name) <= 35:
                    self.name = name
                else:
                    raise ValueError("'name', must be less than 35 chars or less")
            else:
                raise ValueError("'name', must be a string")

    def set_phase1name(self, phase1name):
        """ Set self.phase1name to phase1name if phase1name valid

        Args:
            phase1name (str): phase1name to bind to

        Returns:
            None
        """
        if phase1name is None:
            self.phase1name = None

        else:
            if phase1name.isspace(): raise ValueError("'phase1name', cannot be an empty string")
            if isinstance(phase1name, str):
                if len(phase1name) <= 35:
                    self.phase1name = phase1name
                else:
                    raise ValueError("'phase1name', must be less than 35 chars or less")
            else:
                raise ValueError("'phase1name', must be a string")

    def set_proposal(self, proposal):
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
            self.propsoal = None

        else:
            proposal_items = ''

            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list
            if isinstance(proposal, str):

                # compare proposal to valid_proposals list
                if proposal in valid_proposals:
                    proposal_items += f"{proposal}"
                else:
                    raise ValueError(f"'proposal' provided: {proposal} is not a valid fortigate phase1 proposal option")

            elif isinstance(proposal, list):
                for item in proposal:
                    if isinstance(item, str):

                        # compare proposal to valid proposals list
                        if item in valid_proposals:
                            proposal_items += f" {item}"
                        else:
                            raise ValueError(f"'proposal' provided: {proposal} is not a valid fortigate phase1 proposal"
                                            " option")
            else:
                raise ValueError("'proposal' must be provided as type string (with single proposal referenced or as a "
                                 "list for multiple proposal references")

            self.proposal = proposal_items

    def set_dhgrp(self, dhgrp):
        """  Set self.dhgrp to string containing values dhgrp if dhgrp contains valid FortiGate proposals

        The dhgrp may be passed in as a str, or a list.  If the dhgrp(s) passed in are valid we'll add each
        of those to a space separated values string and set in self.dhgrp

        Args:
            dhgrp (list): list of valid fortigate dhgrps

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
                    dhgrp_items += f"{dhgrp} "
                else:
                    raise ValueError(f"'dhgrp' provided: {dhgrp}, is not a valid fortigate dhgrp")

            elif isinstance(dhgrp, list):
                for item in dhgrp:
                    if isinstance(item, int):

                        # compare proposal to valid proposals list
                        if item in valid_dhgrps:
                            dhgrp_items += f"{item} "
                        else:
                            raise ValueError(f"At least one 'dhgrp' provided: {dhgrp} is not a valid fortigate phase1 "
                                             "proposal option")
            else:
                raise ValueError("dhgrp must be provided as type int() or list() of int()")

            self.dhgrp = dhgrp_items

    def set_comment(self, comment):
        """ Set self.comment to comment if comment valid

        Args:
            comment (str): phase2-interface comment

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
                raise ValueError("'description', when set, must be type str()")

    def set_keepalive(self, keepalive):
        """ Set self.keepalive to keepalive if keepalive valid

        Args:
            keepalive (str):  keepalive, allowed values: 'enable' or 'disable'

        Returns:
            None
        """
        if keepalive is None:
            self.keepalive = None

        else:
            if isinstance(keepalive, str):
                if keepalive == 'enable':
                    self.keepalive = 'enable'
                elif keepalive == 'disable':
                    self.keepalive = 'disable'
                else:
                    raise ValueError("'keepalive' allowed values are: 'enable' or 'disable'")

            else:
                raise ValueError("'keepalive', when set, must be type str()")

    def set_pfs(self, pfs):
        """ set self.pfs to enable, disable or None based on pfs value

        Args:
            pfs (str): pfs, allowed values: 'enable'  or 'disable'

        Returns:
            None
        """
        if pfs is None:
            self.pfs = None

        else:
            if isinstance(pfs, str):
                if pfs == 'enable':
                    self.pfs = 'enable'
                elif pfs == 'disable':
                    self.pfs = 'disable'
                else:
                    raise ValueError("'pfs' allowed values are: 'enable' or 'disable'")
            else:
                raise ValueError("'pfs', when set, must be type str()")

    def set_replay(self, replay):
        """ Set self.replay to enable, disable or None

        Args:
            replay (str): replay protection, allowed values: 'enable' or 'disable'

        Returns:
            None
        """
        if replay is None:
            self.replay = None

        else:
            if isinstance(replay, str):
                if replay == 'enable':
                    self.replay = 'enable'
                elif replay == 'disable':
                    self.replay = 'disable'
                else:
                    raise ValueError("'replay', allowed values are: 'enable' or 'disable'")
            else:
                raise ValueError("'pfs', when set, must type str()")

    def set_auto_negotiate(self, auto_negotiate):
        """ Set self.auto_negotiate to enable, disable or None

        Args:
            auto_negotiate (str): auto-negotiation, allowed values: 'enable' or 'disable'

        Returns:
        None
        """
        if auto_negotiate is None:
            self.auto_negotiate = None

        else:
            if isinstance(auto_negotiate, str):
                if auto_negotiate == 'enable':
                    self.auto_negotiate = 'enable'
                elif auto_negotiate == 'disable':
                    self.auto_negotiate = 'disable'
                else:
                    raise ValueError("'auto_negotiate' allowed values: 'enable' or 'disable'")
            else:
                raise ValueError("'pfs', when set, must type bool")

    def set_src_subnet(self, src_subnet):
        """ Set self.src_subnet if src_subnet valid

        Args:
            src_subnet: Source Selector when selector type set to subnet.  Must be valid ipv4 network/mask.

        Returns:
            None
        """
        if src_subnet is None:
            self.src_subnet = None

        else:
            try:
                ipaddress.ip_network(src_subnet)
            except ValueError:
                raise ValueError("'src_subnet', when set, must be a valid ipv4 or ipv6 address")
            else:
                self.src_subnet = src_subnet

    def set_dst_subnet(self, dst_subnet):
        """ Set self.dst_subnet if dst_subnet valid

        Args:
            dst_subnet: Destination Selector when selector type set to subnet.  Must be valid ipv4 network/mask.

        Returns:
            None
        """
        if dst_subnet is None:
            self.dst_subnet = None

        else:
            try:
                ipaddress.ip_network(dst_subnet)
            except ValueError:
                raise ValueError("'dst_subnet', when set, must be a valid ipv4 or ipv6 address")
            else:
                self.dst_subnet = dst_subnet

