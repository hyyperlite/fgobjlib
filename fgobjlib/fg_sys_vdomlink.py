from fgobjlib import FgObject

class FgVdomLink(FgObject):
    """ FgVdomLink class represents FortiGate system vdom-link object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications

    Attributes:
        name (str): Name of vdom-link object
        vdom_enabled (bool):  Vdom enabled on target object True or False
    """

    def __init__(self, name: str = None, vlink_type: str = None, vdom_enabled: bool = None):
        """
        Args:
            name (str): Name of vdom-link object
            vdom_enabled (bool): VDOMs enabled on target FortiGate?  Set to True if VDOMS enabled False if not.
        """

        # Initialize the parent class
        super().__init__(api='cmdb', api_path='system', api_name='vdom-link', cli_path="config system vdom-link",
                         vdom='global', obj_id=name)

        ### Set parent class attributes ###
        # Map instance attribute names to fg attribute names
        self.data_attrs = {'name': 'name', 'vlink_type': 'type'}
        self.cli_ignore_attrs = []

        if vdom_enabled == True: self.vdom_enabled = True

        # Set instance attributes
        self.set_name(name)
        self.set_vlink_type(vlink_type)

        # Update the parent defined obj_to_str attribute with this objects str representation
        self.obj_to_str += f', name={self.name}, vlink_type={self.vlink_type}'


    # Instance Methods
    def set_name(self, name):
        """ Set self.name to name if name is valid

        Args:
            name (str): Name of vdom-link

        Returns:
            None
        """
        if name is None:
            self.name = None

        else:
            if name.isspace(): raise ValueError("'name', cannot be an empty string")
            if isinstance(name, str):
                if 1 <= len(name) <= 11:
                    self.name = name
                else:
                    raise ValueError("'name', must be less than or equal to 11 chars")
            else:
                raise ValueError("'name', must be a string")

    def set_vlink_type(self, vlink_type):
        if vlink_type is None:
            self.vlink_type = None

        else:
            if isinstance(vlink_type, str):
                if vlink_type.lower() == 'ppp':
                    self.vlink_type = 'ppp'
                elif vlink_type.lower() == 'ethernet' or vlink_type == 'eth':
                    self.vlink_type = 'ethernet'
                else:
                    raise ValueError("'vlink_type', when set, must be either ppp or ethernet")
            else:
                raise ValueError("'vlink_type', when set, must be type str")