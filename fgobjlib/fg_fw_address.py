from fgobjlib import FgObject
import ipaddress

class FgFwAddress(FgObject):
    """
    FgFwAddress  represents FortiGate firewall address object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications.

    Currently supports address types subnet (default), iprange and fqdn

    Attributes:
        data_attrs (dict): Dictionary to define relevant config attributes and map instance attr names to fg attr names
        cli_ignore_attrs (list): List of attributes to ignore when generating CLI configurations
        name (str): Name of instance object
        type (str): Type of address object
        subnet (str): Subnet for "ipmask" type object
        fqdn (str): Fqdn for "fqdn" type object
        start_ip (str): start-ip for "iprange" type object
        end_ip (str): end-ip for "iprange: type object
        visibility (bool): Object visibility set to True or False
        comment (str): Object comment
    """

    def __init__(self, name: str = None, type: str = None, subnet: str = None, fqdn: str = None,
                 start_ip: str = None, end_ip: str = None, visibility: bool = None, associated_interface: str = None,
                 vdom: str = None, comment: str = None):
        """
        Args:
            name (str): required - Name of object.  Defines name used in configs when API or CLI for config methods
            type (str): optional - Set type of address object.  (default: ipmask)
            subnet (str): optional - Set subnet for address object of type ipmask. (default: None)
            fqdn (str): optional - Set fqdn for address object of type fqdn. (default: None)
            start_ip (str): optional - Set start-ip for address object of type iprange. (default: None)
            end_ip (str): optional - Set end-ip address object of type iprange. (default: None)
            visibility (bool): optional - Set visibility option to True-[enabled] or False-[disabled]  (default: None)
            associated_interface (str): optional - Set associated-interface for display in FortiGate GUI (default: None)
            comment (str): optional - Set a comment up to 255 characters (default: None)
            vdom (str): optional - Set vdom.  If unset object configs uses default fg context (default: None)
        """

        # Initialize the parent class
        super().__init__(api='cmdb', api_path='firewall', api_name='address',  cli_path="config firewall address",
                         obj_id=name, vdom=vdom)

        ### Set parent class attributes ###
        # Map instance attribute names to fg attribute names
        self.data_attrs = {'name': 'name', 'type': 'type', 'subnet': 'subnet', 'fqdn': 'fqdn',
                           'associated_interface': 'associated-interface', 'visibility': 'visibility',
                           'comment': 'comments', 'start_ip': 'start-ip', 'end_ip': 'end-ip'}

        self.cli_ignore_attrs = []

        # Set instance attributes
        self.set_name(name)
        self.set_type(type)
        self.set_subnet(subnet)
        self.set_fqdn(fqdn)
        self.set_visibility(visibility)
        self.set_associated_interface(associated_interface)
        self.set_comment(comment)
        self.set_range_ips(start_ip, end_ip)

        # Update the parent defined obj_to_str attribute with this objects str representation
        self.obj_to_str += f', name={self.name}, type={self.type}, subnet={self.subnet}, fqdn={self.fqdn}, ' \
                          f'start_ip={self.start_ip}, visibility={self.visibility}, ' \
                          f'associated_interface={self.associated_interface}, comment={self.comment}'


    # Instance methods
    def set_name(self, name):
        """  Set self.name attribute to name if name provided is valid for FG object

        Args:
            name (str): Name of firewall address object.

        Returns:
            None
        """

        if name is None:
            self.name = None

        else:
            if name.isspace(): raise Exception("'name', cannot be an empty string")
            if isinstance(name, str):
                if 1 <= len(name) <= 79:
                    self.name = name
                else:
                    raise Exception("'name', must be less than or equal to 79 chars")
            else:
                raise Exception("'name', must be a string")

    def set_type(self, type):
        """ Set self.type attribute to type if type provided is valid for FG object

        Args:
            type (str): Type of firewall object, may be 'ipmask', 'iprange', 'fqdn' or None (None = FG Default)

        Returns:
            None
        """
        if type is None:
            self.type = None

        else:
            if type in ['ipmask', 'iprange', 'fqdn']:
                self.type = type
            else:
                raise ValueError("Interface 'type' specified is unsupported")

    def set_subnet(self, subnet):
        """ Set self.subnet to subnet if subnet is valid ipv4 network/mask

        Args:
            subnet (str): valid ipv4 network/mask, for use when self's 'type' is ipmask or None (which is default type)

        Returns:
            None
        """
        if subnet is None:
            self.subnet = None

        else:
            if isinstance(subnet, str):
                try:
                    self.subnet = str(ipaddress.ip_network(subnet))
                except ValueError:
                    raise ValueError("'subnet', when specified must be a valid ipv4 address")

    def set_fqdn(self, fqdn):
        """ Set self.fqdn to fqdn if fqdn provided meets FortiGate requirements for this parameter

        Args:
            fqdn (str): fqdn for use when self type is also set to 'fqdn'

        Returns:
            None
        """
        if fqdn is None:
            self.fqdn = None

        else:
            if 1 <= len(fqdn) <= 255:
                self.fqdn = fqdn
            else:
                raise ValueError("'fqdn', when set, must be type str between 1 and 255 chars")

    def set_visibility(self, visibility):
        """ Set self.visibility

        Args:
            visibility (bool): Boolean to set visibility on FortiGate to enabled (True) or disabled (False)

        Returns:
            None
        """
        if visibility is None:
            self.visibility = None

        else:
            if isinstance(visibility, bool):
                self.visibility = 'enable' if visibility else 'disable'
            else:
                raise ValueError("'visibility', when set, must be type bool")

    def set_associated_interface(self, intf):
        """ Set self.associated_interface if associated_interface provided meets requirements

        Args:
            intf (str):

        Returns:
            None
        """
        if intf is None:
            self.associated_interface = None

        else:
            if intf.isspace(): raise Exception("'associated_interface', cannot be an empty string")
            if isinstance(intf, str):
                if 1 <= len(intf) <= 35:
                    self.associated_interface = intf
                else:
                    raise Exception("'associated_interface', when set, must be between 1 and 35 chars")
            else:
                raise Exception("'name', must be a string")

    def set_comment(self, comment):
        """ Set self.comment if comment provided meets requirements

        Args:
            comment (str): Comment for this FG object

        Returns:
            None
        """
        if comment is None:
            self.comment = None

        else:
            if isinstance(comment, str):
                if 1 <= len(comment) <= 255:
                    self.comment = comment
                else:
                    raise Exception("'description', when set, must be type str between 1 and 1,023 chars")
            else:
                raise Exception("'description', when set, must be type str")

    def set_range_ips(self, start_ip, end_ip):
        """ Set self.start_ip and self.end_ip if valid

        Validates start and end IPs to verify valid IPv4 address and that start_ip is sequentially less than end_ip
        (Range IPs should generally only be invoked when self.type is set to 'iprange')

        Args:
            start_ip (str):  Valid IPv4 address for start-ip
            end_ip (str):  Valid IPv4 address for end-ip

        Returns:
            None
        """
        if start_ip and end_ip:
            try:
                self.start_ip = str(ipaddress.ip_address(start_ip))
            except ValueError:
                raise ValueError("'start_ip', when set must be a valid ipv4 or ipv6 address")
            try:
                self.end_ip = str(ipaddress.ip_address(end_ip))
            except ValueError:
                raise ValueError("'end_ip', when set, must be a valid ipv4 or ipv6 address")

            if ipaddress.ip_address(start_ip) < ipaddress.ip_address(end_ip):
                pass
            else:
                raise ValueError("'end_ip' must be higher IP address than 'start_ip'")
        elif start_ip or end_ip:
            raise ValueError("When setting iprange parameters both 'start_ip' and 'end_ip' must be set with valid "
                             "ip addresses")
        else:
            self.start_ip = None
            self.end_ip = None