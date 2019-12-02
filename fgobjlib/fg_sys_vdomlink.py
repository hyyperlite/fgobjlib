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

        # Set parent class attributes #
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'name': 'name', 'vlink_type': 'type'}
        self._cli_ignore_attrs = []

        if vdom_enabled is True:
            self.vdom_enabled = True

        # Set instance attributes
        self.name = name
        self.vlink_type = vlink_type

        # Update the parent defined obj_to_str attribute with this objects str representation
        self._obj_to_str += f', name={self.name}, vlink_type={self.vlink_type}'

    # Instance properties and setters
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        """ Set self.name to name if name is valid

        Args:
            name (str): Name of vdom-link

        Returns:
            None
        """
        if name is None:
            self._name = None

        else:
            if name.isspace():
                raise ValueError("'name', cannot be an empty string")
            if isinstance(name, str):
                if 1 <= len(name) <= 11:
                    self._name = name
                else:
                    raise ValueError("'name', must be type str() between 1 and 11 chars")
            else:
                raise ValueError("'name', must be type str()")

    @property
    def vlink_type(self):
        return self.vlink_type

    @vlink_type.setter
    def vlink_type(self, vlink_type):
        if vlink_type is None:
            self._vlink_type = None

        else:
            if isinstance(vlink_type, str):
                if vlink_type.lower() == 'ppp':
                    self._vlink_type = 'ppp'
                elif vlink_type.lower() == 'ethernet' or vlink_type == 'eth':
                    self._vlink_type = 'ethernet'
                else:
                    raise ValueError("'vlink_type', when set, must be type str with values either 'ppp' or 'ethernet'")
            else:
                raise ValueError("'vlink_type', when set, must be type str()")
