from fgobjlib import FgObject
import ipaddress

class FgIpsecP2Interface(FgObject):
    """
    FgIpsecP2Interface class represents FortiGate Firewall ipsec phase2 interface object and provides methods for
    validating parameters and generating both cli and api configuration data for use in external configuration
    applications and ftntlib

    Currently supports dynamic or static VPN using psk authentication. No support yet for advpn or mode-cfg
    """

    def __init__(self, name: str = None, phase1name: str = None, proposal: list = None, pfs: bool = None,
                 dhgrp: int = None, keepalive: int = None, replay: bool = None, comment: str = None,
                 auto_negotiate: bool = None, vdom: str = None, src_subnet: str = None, dst_subnet: str = None):

        # Set instance attributes
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

        # Initialize the parent class
        super().__init__(vdom=vdom, api='cmdb', api_path='vpn.ipsec', api_name='phase2-interface', api_mkey=None,
                         obj_id=self.name)

        ### Set parent class attributes ###
        # CLI config path for this object type
        self.cli_path = "config vpn ipsec phase2-interface"

        # Map instance attribute names to fg attribute names
        self.data_attrs = {'name': 'name', 'phase1name': 'phase1name', 'proposal': 'proposal',
                           'comment': 'comments', 'keepalive': 'keepalive', 'dhgrp': 'dhgrp', 'pfs': 'pfs',
                           'replay': 'replay', 'auto_negotiate': 'auto-negotiate', 'src_subnet': 'src-subnet',
                           'dst_subnet': 'dst-subnet'}


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

    def set_phase1name(self, name):
        if name:
            if name.isspace(): raise Exception("\"phase1_name\", cannot be an empty string")
            if isinstance(name, str):
                if len(name) <= 35:
                    self.phase1name = name
                else:
                    raise Exception("\"phase1_name\", must be less than 35 chars or less")
            else:
                raise Exception("\"phase1_name\", must be a string")
        else:
            raise Exception("Value \"phase1_name\" is required but was not provided")

    def set_proposal(self, proposal):
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

        if proposal:
            proposal_items = ''

            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list
            if isinstance(proposal, str):

                # compare proposal to valid_proposals list
                if proposal in valid_proposals:
                    proposal_items += "{}".format(proposal)
                else:
                    raise Exception("\"proposal\" provided: {} is not a valid fortigate phase1 proposal "
                                    "option".format(proposal))

            elif isinstance(proposal, list):
                for item in proposal:
                    if isinstance(item, str):

                        # compare proposal to valid proposals list
                        if item in valid_proposals:
                            proposal_items += " {}".format(item)
                        else:
                            raise Exception("\"proposal\" provided: {} is not a valid fortigate phase1 proposal "
                                            "option".format(proposal))
            else:
                raise Exception("proposal must be provided as type string (with single proposal referenced or as a list "
                                "for multiple proposal references")

            self.proposal = proposal_items

        else:
            raise Exception("\"proposal\" is required but not provided")

    def set_dhgrp(self, dhgrp):
        """
        set_dhgrp: the dhgrp may be passed in as a str, or a list.  If the dhgrp(s) passed in are valid we'll add each
        of those to a space separated values string and set in self.dhgrp

        :param dhgrp:
        :return:
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

    def set_pfs(self, pfs):
        if pfs:
            if isinstance(pfs, bool):
                self.pfs = 'enable' if pfs else 'disable'
            else:
                raise Exception("\"pfs\", when set, must type bool")
        else:
            self.pfs = None

    def set_replay(self, replay):
        if replay:
            if isinstance(replay, bool):
                self.replay = 'enable' if replay else 'disable'
            else:
                raise Exception("\"pfs\", when set, must type bool")
        else:
            self.replay = None

    def set_auto_negotiate(self, auto_negotiate):
        if auto_negotiate:
            if isinstance(auto_negotiate, bool):
                self.auto_negotiate = 'enable' if auto_negotiate else 'disable'
            else:
                raise Exception("\"pfs\", when set, must type bool")
        else:
            self.auto_negotiate = None

    def set_src_subnet(self, src_subnet):
        if src_subnet:
            try:
                ipaddress.ip_network(src_subnet)
            except ValueError:
                print("\"src_subnet\", when set, must be a valide ipv4 or ipv6 address")
            else:
                self.src_subnet = src_subnet
        else:
            self.src_subnet = None

    def set_dst_subnet(self, dst_subnet):
        if dst_subnet:
            try:
                ipaddress.ip_network(dst_subnet)
            except ValueError:
                print("\"dst_subnet\", when set, must be a valide ipv4 or ipv6 address")
            else:
                self.dst_subnet = dst_subnet
        else:
            self.dst_subnet = None


