from fgobjlib import FgObject


class FgVdomLink(FgObject):
    """
    FgInterface class represents FortiGate Firewall interface object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications

    Currently supports interface types of \"standard\" i.e. ethernet/physical or vlan,
    """

    def __init__(self, name: str = None, vdom_enabled: bool = None):

        # Set instance attributes
        self.set_name(name)

        # Initialize the parent class
        super().__init__(vdom='global', api='cmdb', api_path='system', api_name='vdom-link', api_mkey=None,
                         obj_id=self.name)

        if vdom_enabled == True:
            self.vdom_enabled = True

        ### Set parent class attributes ###
        # CLI config path for this object type
        self.cli_path = "config system vdom-link"

        # Map instance attribute names to fg attribute names
        self.data_attrs = {'name': 'name'}
        self.cli_ignore_attrs = []

    def set_name(self, name):
        if name:
            if name.isspace(): raise Exception("\"intf\", cannot be an empty string")
            if isinstance(name, str):
                if 1 <= len(name) <= 11:
                    self.name = name
                else:
                    raise Exception("\"name\", must be less than or equal to 11 chars")
            else:
                raise Exception("\"name\", must be a string")
        else:
            raise Exception("Value \"name\" is required but was not provided")

