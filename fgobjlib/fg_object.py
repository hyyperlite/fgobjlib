from abc import ABC

class FgObject(ABC):
    """FgObject class represents basic methods and attributes used commonly across most, if not all, child class objects

    This is an abstract class and as such cannot be instantiated directly.

    FgObject class provides attributes and methods that are used by the specific FortiGate object child classes.  Common
    attributes such as VDOM and object ID are contained and validated in this parent class.  API and CLI path attributes
    are also represented here.  Various methods used by most of the child classes for returning CLI or API configuration
    data are also within this FgObject class. This class is typically not called directly by an application, rather it
    is extended by the specific FortiGate object child classes such as FgFwPolicy.

    Attributes:
        API (str): string representing the FortiGate API to be called.  (this will almost always be 'cmdb')
        API_PATH (str): string representing the api path associated with this object. (ex. system, router, firewall, etc..)
        API_NAME (str): string representing the object type within the api_path to add/update/delete/get.
        API_MKEY: updated with object_id for update/delete/get operations
        CLI_PATH (str):  string with base FG cli context configurations for this object (ex: "config system interface")
        obj_id: this may be string, integer or other type that defines the object ID for use in api and cli config.
        vdom: defines the vdom this object is to be configured/updated/deleted/got from.
        vdom_enabled: used for objects which "may" be configured from global context to determine correct cli config path
        is_global (bool): Set if the object should be configured from global context only
"""

    def __init__(self, api: str = None, api_path: str = None, api_name: str = None,  cli_path = None,
                 obj_id = None, vdom: str = None):
        """
        Args:
            api (str): set the FortiGate API to use. (default None) - Required if using API config methods.
            api_path (str): optional - set the FortiGate API path. (default None) - Required if using API config methods.
            api_name (str): optional - set the FortiGate API name.  (default None) - Required if using API config methods
            cli_path (str): optional - set the FortiGate CLI configuration path . (default None) -
            Required if using CLI config methods
            obj_id: required - set the object id, this may be str or int.
            vdom (str): optional - set the objects vdom, if FG vdoms enabled and object type is configured in vdom context
        """

        # Set the API path
        self.API = api
        self.API_PATH = api_path
        self.API_NAME = api_name
        self.API_MKEY = None

        # Set the CLI path
        self.CLI_PATH = cli_path

        # Set attrs
        self.obj_id = obj_id
        self.vdom = vdom

        # Set and used only for objects that are configured via global context vs vdom context
        # these allow to determine if cli should use "config system global" or just configure the object
        # depending on whether vdom is enabled
        self.vdom_enabled = None
        self.is_global = None

        # Map of instance attribute names to fg attribute names
        self._data_attrs = {}
        # In CLI config output some attributes in data_attrs may not be needed. So set which to ignore for CLI
        self._cli_ignore_attrs = {}

        # For use in string output of object such as dunder methods __str__ and __repr__
        self._obj_to_str = f'obj_id={self.obj_id}, vdom={self.vdom}'

    # Instance to string dunder methods
    def __str__(self):
        return self._obj_to_str

    def __repr__(self):
        return self._obj_to_str

    # Property Methods
    @property
    def vdom(self):
        return self._vdom

    @vdom.setter
    def vdom(self, vdom):
        """ Validate the vdom argument for FortiGate consumption, if acceptable set to self.vdom

        Verify that vdom argument is non-empty string, with no whitespace between 1 and 31 chars.  If valid then set
        self.vdom = vdom

        Args:
            vdom (str): FortiGate VDOM name that the instance object should be tied to

        Returns:
            None
        """
        if vdom is None:
            self._vdom = None

        else:
            if isinstance(vdom, str):
                # vdom names cannot have spaces so check for spaces and throw error if there are
                for char in vdom:
                    if str.isspace(char):
                        raise ValueError("'vdom', when set, must be str with no whitespace")

                # Check vdom name string length meets FG requirements
                if 1 <= len(vdom) <= 31:
                    self._vdom = vdom
                else:
                    raise ValueError("'vdom', when set, must be a str between 1 and 31 chars")
            else:
                raise ValueError("'vdom', when set, must be a str between 1 and 31")

    # API Config Methods
    def get_api_config_add(self):
        """ Get FortiGate API configuration for adding(post) self to FortiGate via API using Fortinet's ftntlib library

        Based on currently set instance attributes this method will build and return a FortiGate API configuration
        parameters to be used in making Rest API post call to FortiGate using ftntlib.  (ftntlib is a library for
        simplifying REST API calls to FortiOS and can be downloaded from the Fortinet Developer Network at
        https://fndn.fortinet.net)

        Args:
            self: the current instance object

        Returns:
            A dictionary mapping keys to corresponding ftnlib API attributes  for ftntlib REST API methods.

            example:
                {'api': 'cmdb',
                'path': 'vpn.ipsec',
                'name': 'phase1-interface',
                'mkey': 'vpn1',
                'action': None,
                'data': {},
                'parameters': {'vdom': 'vdom1'}}
        """

        conf = {'api': self.API, 'path': self.API_PATH, 'name': self.API_NAME, 'mkey': self.API_MKEY, 'action': None}
        data = {}
        params = {}

        # Set the VDOM, if necessary
        if self.is_global:
            pass
        elif self.vdom:
            if self.vdom == 'global':
                pass
            else:
                params.update({'vdom': self.vdom})

        for inst_attr, fg_attr in self._data_attrs.items():
            if getattr(self, inst_attr): data.update({fg_attr: getattr(self, inst_attr)})

        # Add data and parameter dictionaries to conf dictionary
        conf.update({'data': data})
        conf.update({'parameters': params})

        return conf

    def get_api_config_update(self):
        """ Get FortiGate API configuration for updating(put) self to FortiGate via API using Fortinet's ftntlib library

        Based on current instance's attributes this method will build and return a FortiGate API configuration
        parameters to be used in making Rest API put call to FortiGate using ftntlib.  (ftntlib is a library for
        simplifying REST API calls to FortiOS and can be downloaded from the Fortinet Developer Network at
        https://fndn.fortinet.net)

        Args:
            self: the current instance object

        Returns:
            A dictionary mapping keys to corresponding ftnlib API attributes  for ftntlib REST API methods.

            example:
                {'api': 'cmdb',
                'path': 'vpn.ipsec',
                'name': 'phase1-interface',
                'mkey': 'vpn1',
                'action': None,
                'data': {},
                'parameters': {'vdom': 'vdom1'}}
        """

        # Need to set mkey to interface name when doing updates (puts) or deletes
        self.API_MKEY = self.obj_id

        conf = self.get_api_config_add()
        return conf

    def get_api_config_del(self):
        """ Get FortiGate API configuration for deleting(delete) self from FortiGate via API using Fortinet ftntlib lib

        Based on current instance's attributes this method will build and return a FortiGate API configuration
        parameters to be used in making Rest API delete call to FortiGate using ftntlib.  (ftntlib is a library for
        simplifying REST API calls to FortiOS and can be downloaded from the Fortinet Developer Network at
        https://fndn.fortinet.net)

        Args:
            self: the current instance object

        Returns:
            A dictionary mapping keys to corresponding ftnlib API attributes  for ftntlib REST API methods.

            example:
                {'api': 'cmdb',
                'path': 'vpn.ipsec',
                'name': 'phase1-interface',
                'mkey': 'vpn1',
                'action': None,
                'data': {},
                'parameters': {'vdom': 'vdom1'}}

        """
        conf = {'api': self.API, 'path': self.API_PATH, 'name': self.API_NAME, 'mkey': self.API_MKEY, 'action': None}
        data = {}
        params = {}

        # Set the VDOM, if necessary
        if self.vdom:
            if self.vdom == 'global':
                pass
            else:
                params.update({'vdom': self.vdom})

        if self.obj_id:
            # Set the mkey value to interface name and updated other vars
            conf['mkey'] = self.obj_id
            conf.update({'data': data})
            conf.update({'parameters': params})

        else:
            raise Exception("\"name\" must be set in order get or delete an existing policy")

        return conf

    def get_api_config_get(self):
        """ Get FortiGate API configuration for getting(get) self from FortiGate via API using Fortinet ftntlib lib

            Based on current instance's attributes this method will build and return a FortiGate API configuration
            parameters to be used in making Rest API get call to FortiGate using ftntlib.  (ftntlib is a library for
            simplifying REST API calls to FortiOS and can be downloaded from the Fortinet Developer Network at
            https://fndn.fortinet.net)

        Args:
            self: the current instance object

        Returns:
            A dictionary mapping keys to corresponding ftnlib API attributes  for ftntlib REST API methods.

            example:
                {'api': 'cmdb',
                'path': 'vpn.ipsec',
                'name': 'phase1-interface',
                'mkey': 'vpn1',
                'action': None,
                'data': {},
                'parameters': {'vdom': 'vdom1'}}
            """
        conf = self.get_api_config_del()
        return conf

    # CLI Config Methods
    def get_cli_config_add(self):
        """ Get FortiGate CLI configuration for adding self to FortiGate via CLI

            Based on currently set instance attributes this method will build and return a FortiGate CLI configuration
            snippet for the current instance object.

            Args:
                self: the current instance object

            Returns:
                A FortiGate CLI configuration snippet representing self to be use for configuring new FG object.
            """

        conf = ''

        # start vdom or global config
        if self.vdom:
            if self.vdom == 'global' and self.vdom_enabled:
                conf += "config global\n"
            else:
                conf += "config vdom\n"
                conf += f" edit {self.vdom} \n"

        # Config object's cli path
        conf += f"{self.CLI_PATH}\n"

        # Edit obj_id
        conf += f"  edit \"{self.obj_id}\" \n"

        # For every attr defined in the data_attrs dictionary, if the dictionary value is true then add it to the
        # configuration.  Otherwise skip it.
        for inst_attr, fg_attr in self._data_attrs.items():

            # Check for cli attribute in ignore list and skip if contained
            if inst_attr in self._cli_ignore_attrs: continue

            # get the value of an attribute based on the text name of the attribute in data_attrs dictionary
            config_attr = getattr(self, inst_attr)

            # need to convert lists which are used for api, to strings for cli output
            if isinstance(config_attr, list):
                str_items = ''

                # if the config item is a list, then get the dictionaries from that list, pull the value and assign
                # the value to a string that will be used as the config parameters in the cli config output
                for item in config_attr:
                    if isinstance(item, dict):
                        if item['name']:
                            str_items += f"{item.get('name')} "
                        else:
                            raise Exception(f"unrecognized key name for dictionary list: {item.keys()}")

                conf += f"    set {fg_attr} \"{str_items}\"\n"
            else:
                if getattr(self, inst_attr): conf += "    set {fg_attr} \"{config_attr}\"\n"

        # End obj_id config
        conf += "  end\nend\n"

        # End vdom or global config
        if self.vdom:
            if self.vdom == 'global' and self.vdom_enabled:
                conf += "end\n"
            elif self.vdom == 'global':
                pass
            else:
                conf += "end\n"

        return conf

    def get_cli_config_update(self):
        """ Get FortiGate CLI configuration for updating self to FortiGate via CLI

        Based on currently set instance attributes this method will build and return a FortiGate CLI configuration
        snippet for the current instance object.

        Args:
            self: the current instance object

        Returns:
            A FortiGate CLI configuration snippet representing self to be use for updating existing FG object
        """
        conf = self.get_cli_config_add()
        return conf

    def get_cli_config_del(self):
        """ Get FortiGate CLI configuration for deleting self from FortiGate via CLI

            Based on currently set instance attributes this method will build and return a FortiGate CLI configuration
            snippet for the current instance object.

            Args:
                self: the current instance object

            Returns:
                A FortiGate CLI configuration snippet representing self to be use for configuring new FG object
            """
        conf = ''
        if self.obj_id:

            # start vdom or global config
            if self.vdom:
                if self.vdom == 'global' and self.vdom_enabled:
                    conf += "config global\n"
                else:
                    conf += "config vdom\n"
                    conf += f" edit {self.vdom} \n"

            conf += f"{self.CLI_PATH}\n"
            conf += f"  delete {self.obj_id}\n"
            conf += "end\n"

            # End vdom or global config
            if self.vdom:
                if self.vdom == 'global' and self.vdom_enabled:
                    conf += "end\n"
                elif self.vdom == 'global':
                    pass
                else:
                    conf += "end\n"

            return conf
        else:
            raise Exception("'obj_id' must be set in order to configure it for delete")
