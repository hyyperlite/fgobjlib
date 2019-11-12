from fgobjlib import FgObject
import ipaddress

class FgFwAddress(FgObject):
    """
    FgFwAddress class represents FortiGate Firewall address object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications

    Currently supports address type subnet (default), iprange and fqdn
    """

    def __init__(self, name: str = None, type: str = None, address: str = None, visibility: bool = None,
                 associated_interface: str = None, vdom: str = None, comment: str = None):

        # Initialize the parent class
        super().__init__(api='cmdb', api_path='firewall', api_name='address', api_mkey=None, obj_id=name, vdom=vdom)

        ### Set parent class attributes ###
        # CLI config path for this object type
        self.cli_path = "config firewall address"

        # Map instance attribute names to fg attribute names
        self.data_attrs = {'name': 'name', 'type': 'type', 'address': 'subnet',
                           'associated_interface': 'associated-interface', 'visibility': 'visibility',
                           'comment': 'comments'}

        self.cli_ignore_attrs = []

        # Set instance attributes
        self.set_name(name)
        self.set_type(type)
        self.set_address(address)
        self.set_visibility(visibility)
        self.set_associated_interface(associated_interface)
        self.set_comment(comment)


    def set_name(self, name):
        if name:
            if name.isspace(): raise Exception("\"intf\", cannot be an empty string")
            if isinstance(name, str):
                if 1 <= len(name) <= 79:
                    self.name = name
                else:
                    raise Exception("\"name\", must be less than or equal to 79 chars")
            else:
                raise Exception("\"name\", must be a string")
        else:
            raise Exception("Value \"name\" is required but was not provided")

    def set_type(self, type):
        if type:
            if type in ['ipmask', 'iprange', 'fqdn']:
                self.type = type
            else:
                raise ValueError("\"type\" specified is unsupported")
        else:
            self.type = None

    def set_address(self, address):
        if address:
            if isinstance(address, str):
                # subnets
                if self.type:
                    if self.type == 'ipmask':
                        self.data_attrs.update({'address': 'subnet'})
                        try:
                            self.address = str(ipaddress.ip_network(address))
                        except ValueError:
                            raise ValueError("\"address\", when inst type is \"subnet\" or default, "
                                             "must be a valid ipv4 or ipv6 network and subnet")
                    # FQDNs
                    elif self.type == 'fqdn':
                        if 1 <= len(address) <= 255:
                            self.address = address
                            self.data_attrs.update({'address': 'fqdn'})

                    # iprange, requires address string to contain form: <ipaddress>-<ipaddress>, which will be split
                    # into a start-ip and end-ip for address object
                    elif self.type == 'iprange':
                        start_ip, end_ip = address.split('-')
                        self.data_attrs.update({'start_ip': 'start-ip'})
                        self.data_attrs.update({'end_ip': 'end-ip'})
                        try:
                            self.start_ip = str(ipaddress.ip_address(start_ip))
                        except ValueError:
                            raise ValueError("\"start-ip\", must be a valid ipv4 or ipv6 address")
                        try:
                            self.end_ip = str(ipaddress.ip_address(end_ip))
                        except ValueError:
                            raise ValueError("\"end-ip\", must be a valid ipv4 or ipv6 address")

                        self.address = None

                    else:
                        raise Exception("could not determine what to do with address based on provided \"type\": "
                                        " {}".format(self.type))

                # Else, assume/default type is ipmask
                else:
                    self.data_attrs.update({'address': 'subnet'})
                    try:
                        self.address = str(ipaddress.ip_network(address))
                    except ValueError:
                        raise ValueError("\"address\", when inst type is \"subnet\" (default), "
                                         "must be a valid ipv4 or ipv6 network and subnet")

            else:
                raise ValueError("\"target\" must be type str")
        else:
            self.address = None

    def set_visibility(self, visibility):
        if visibility:
            if isinstance(visibility, bool):
                self.visibility = 'enable' if visibility else 'disable'
            else:
                raise ValueError("\"visibility\", when set, must be type bool")
        else:
            self.visibility = None

    def set_associated_interface(self, intf):
        if intf:
            if intf.isspace(): raise Exception("\"associated_interface\", cannot be an empty string")
            if isinstance(intf, str):
                if 1 <= len(intf) <= 35:
                    self.associated_interface = intf
                else:
                    raise Exception("\"associated_interface\", when set, must be between 1 and 35 chars")
            else:
                raise Exception("\"name\", must be a string")

        else:
            self.associated_interface = None

    def set_comment(self, comment):
        if comment:
            if isinstance(comment, str):
                if 1 <= len(comment) <= 255:
                    self.comment = comment
                else:
                    raise Exception("\"description\", when set, must be type str between 1 and 1,023 chars")
            else:
                raise Exception("\"description\", when set, must be type str")
        else:
            self.comment = None