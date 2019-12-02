import ipaddress

from fgobjlib import FgObject


class FgFwAddress(FgObject):
    """
    FgFwAddress  represents FortiGate firewall address object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications.

    Currently supports address types subnet (default), iprange and fqdn

    Attributes:
        name (str): Name of instance object
        type (str): Type of address object
        subnet (str): Subnet for "ipmask" type object
        fqdn (str): Fqdn for "fqdn" type object
        start_ip (str): start-ip for "iprange" type object
        end_ip (str): end-ip for "iprange: type object
        visibility (str): Object visibility ('enable', 'disable', or None=inherit)
        comment (str): Object comment
    """

    def __init__(self, name: str = None, type: str = None, subnet: str = None, fqdn: str = None,
                 start_ip: str = None, end_ip: str = None, visibility: str = None, associated_interface: str = None,
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

        # Set parent class attributes #
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'name': 'name', 'type': 'type', 'subnet': 'subnet', 'fqdn': 'fqdn',
                            'associated_interface': 'associated-interface', 'visibility': 'visibility',
                            'comment': 'comments', 'start_ip': 'start-ip', 'end_ip': 'end-ip'}

        self._cli_ignore_attrs = []

        # Set instance attributes
        self.name = name
        self.type = type
        self.subnet = subnet
        self.fqdn = fqdn
        self.visibility = visibility
        self.associated_interface = associated_interface
        self.comment = comment
        self.start_ip = start_ip
        self.end_ip = end_ip

        # Update the parent defined obj_to_str attribute with this objects str representation
        self._obj_to_str += f', name={self.name}, type={self.type}, subnet={self.subnet}, fqdn={self.fqdn}, ' \
                            f'start_ip={self.start_ip}, visibility={self.visibility}, ' \
                            f'associated_interface={self.associated_interface}, comment={self.comment}'

    # Instance Properties and Setters
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        """  Set self.name attribute to name if name provided is valid for FG object

        Args:
            name (str): Name of firewall address object.

        Returns:
            None
        """

        if name is None:
            self._name = None

        else:
            if isinstance(name, str):
                if name.isspace():
                    raise ValueError("'name', cannot be an empty string")
                if 1 <= len(name) <= 79:
                    self._name = name
                else:
                    raise ValueError("'name', must be type str() 79 chars or less")
            else:
                raise ValueError("'name', must be type str()")

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, type):
        """ Set self.type attribute to type if type provided is valid for FG object

        Args:
            type (str): Type of firewall object, may be 'ipmask', 'iprange', 'fqdn' or None (None = FG Default)

        Returns:
            None
        """
        if type is None:
            self._type = None

        else:
            if isinstance(type, str):
                if type in ['ipmask', 'iprange', 'fqdn']:
                    self._type = type
                else:
                    raise ValueError("'type', when set, must be type str() with values 'ipmask', 'iprange "
                                     "or 'fqdn'")
            else:
                raise ValueError("'type', when set, must be type str()")

    @property
    def subnet(self):
        return self._subnet

    @subnet.setter
    def subnet(self, subnet):
        """ Set self.subnet to subnet if subnet is valid ipv4 network/mask

        Args:
            subnet (str): valid ipv4 network/mask, for use when self's 'type' is ipmask or None (which is default type)

        Returns:
            None
        """
        if subnet is None:
            self._subnet = None
        else:
            if isinstance(subnet, str):
                try:
                    self._subnet = str(ipaddress.ip_network(subnet))
                except ValueError:
                    raise ValueError("'subnet', when specified must be type str with value of a valid ipv4 address")
            else:
                raise ValueError("'subnet', when set, must be type str() with value of a valid ipv4 address")

    @property
    def fqdn(self):
        return self._fqdn

    @fqdn.setter
    def fqdn(self, fqdn):
        """ Set self.fqdn to fqdn if fqdn provided meets FortiGate requirements for this parameter

        Args:
            fqdn (str): fqdn for use when self type is also set to 'fqdn'

        Returns:
            None
        """
        if fqdn is None:
            self._fqdn = None

        elif isinstance(fqdn, str):
            if 1 <= len(fqdn) <= 255:
                self._fqdn = fqdn
            else:
                raise ValueError("'fqdn', when set, must be type str() between 1 and 255 chars")
        else:
            raise ValueError("'fqdn', when set, must be type str()")

    @property
    def visibility(self):
        return self._visibility

    @visibility.setter
    def visibility(self, visibility):
        """ Set self.visibility

        Args:
            visibility (str): object visibility in GUI.  ('enable', 'disable', or None=inherit)

        Returns:
            None
        """
        if visibility is None:
            self._visibility = None
        else:
            if isinstance(visibility, str):
                if visibility == 'enable':
                    self._visibility = 'enable'
                elif visibility == 'disable':
                    self._visibility = 'disable'
                else:
                    raise ValueError("'visibility', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'visibility', when set, must be type str()")

    @property
    def associated_interface(self):
        return self._associated_interface

    @associated_interface.setter
    def associated_interface(self, intf):
        """ Set self.associated_interface if associated_interface provided meets requirements

        Args:
            intf (str): Name of associated interface for GUI display.  (1-35 chars)

        Returns:
            None
        """
        if intf is None:
            self._associated_interface = None

        else:
            if intf.isspace():
                raise ValueError("'associated_interface', when set, cannot be an empty string")
            if isinstance(intf, str):
                if 1 <= len(intf) <= 35:
                    self._associated_interface = intf
                else:
                    raise ValueError("'associated_interface', when set, must be type str() between 1 and 35 chars")
            else:
                raise ValueError("'associated_interface', when set, must be type str()")

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, comment):
        """ Set self.comment if comment provided meets requirements

        Args:
            comment (str): Comment for this FG object

        Returns:
            None
        """
        if comment is None:
            self._comment = None

        else:
            if isinstance(comment, str):
                if 1 <= len(comment) <= 255:
                    self._comment = comment
                else:
                    raise ValueError("'comment', when set, must be type str() between 1 and 1,023 chars")
            else:
                raise ValueError("'comment', when set, must be type str()")

    @property
    def start_ip(self):
        return self._start_ip

    @start_ip.setter
    def start_ip(self, start_ip):
        """ Set self.start_ip

       Validates that start_ip, if set is a valid ipv4 address

        Args:
            start_ip (str):  Valid IPv4 address for FortiOS start-ip

        Returns:
            None
        """
        if start_ip is None:
            self._start_ip = None
        else:
            if isinstance(start_ip, str):
                try:
                    self._start_ip = str(ipaddress.ip_address(start_ip))
                except ValueError:
                    raise ValueError("'start_ip', when set must be type str() with value as valid ipv4 address")
            else:
                raise ValueError("'start_ip', when set must be type str() with value a valid ipv4 address")

    @property
    def end_ip(self):
        return self._end_ip

    @end_ip.setter
    def end_ip(self, end_ip):
        """ Set self.end_ip if end_ip is a valid ipv4 address or None

        Args:
            end_ip (str):  Valid IPv4 address for FortiOS end-ip

        Returns:
            None
        """
        if end_ip is None:
            self._end_ip = None
        else:
            if isinstance(end_ip, str):
                try:
                    self._end_ip = str(ipaddress.ip_address(end_ip))
                except ValueError:
                    raise ValueError("'end_ip', when set must be type str() with value as valid ipv4 address")
            else:
                raise ValueError("'end_ip', when set must be type str() with value a valid ipv4 address")
