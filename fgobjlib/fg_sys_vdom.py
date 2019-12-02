from fgobjlib import FgObject

class FgVdom(FgObject):
    """ FGVdom class represents a FortiGate VDOM object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications

    Note: VDOMs must be enabled on FortiGate prior to using results from this object for configuring FortiGates

    Attributes:
        name (str): Name of vdom-link object
    """

    def __init__(self, name: str = None):
        """
        Args:
            name (str): Name of vdom
        """

        # Initialize the parent class
        super().__init__(api='cmdb', api_path='system', api_name='vdom', cli_path="config vdom",
                         vdom='global', obj_id=name)

        # Set parent class attributes #
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'name': 'name'}
        self._cli_ignore_attrs = ['name']

        # Enable global config instead of per VDOM
        self.is_global = True

        # Set instance attributes
        self.name = name

        # Set obj to str conversion
        self._obj_to_str += f', name={self.name}'

    # Instance properties and setters
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        """ Set self.name to name if name is valid

        Args:
            name (str): Name of vdom

        Returns:
            None
        """
        if name:
            if name.isspace():
                raise ValueError("'name', cannot be an empty string")
            for char in name:
                if char.isspace():
                    raise ValueError("'name' may not contain spaces")
            if isinstance(name, str):
                if 1 <= len(name) <= 31:
                    self._name = name
                else:
                    raise ValueError("'name', must be type str() between 1 and 31 chars")
            else:
                raise ValueError("'name', must be type str() between 1 and 31 chars")
        else:
            self._name = None
