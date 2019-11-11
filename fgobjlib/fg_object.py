class FgObject:
    def __init__(self, vdom: str = None, api: str = 'cmdb', api_path: str = None, api_name: str = None,
                 api_mkey: str = None, obj_id = None, cli_path: str = None):

        # Set the API PATH
        self.API = api
        self.API_PATH = api_path
        self.API_NAME = api_name
        self.API_MKEY = api_mkey

        # Set attrs
        self.obj_id = obj_id
        self.cli_path = None
        self.set_vdom(vdom)

        # Set and used only for objects that are configured via global context vs vdom context
        # these allow to determine if cli should use "config system global" or just configure the object
        # depending on whether vdom is enabled
        self.vdom_enabled = None

        # Map of instance attribute names to fg attribute names
        self.data_attrs = {}
        self.cli_ignore_attrs = {}

    def set_vdom(self, vdom):
        if vdom:
            if isinstance(vdom, str):
                # vdom names cannot have spaces so check for spaces and throw error if there are
                for char in vdom:
                    if str.isspace(char):
                        raise Exception("\"vdom\", str not allowed to contain whitespace")

                # Check vdom name string length meets FG requirements
                if 1 <= len(vdom) <= 31:
                    self.vdom = vdom
                else:
                    raise Exception("\"vdom\", when set, must be an str between 1 and 31 chars")
            else:
                raise Exception("\"vdom\", when set, must be a str")
        else:
            self.vdom = None

    ##########################
    #   API Config Methods   #
    ##########################
    def get_api_config_add(self):
        conf = {'api': self.API, 'path': self.API_PATH, 'name': self.API_NAME, 'mkey': self.API_MKEY, 'action': None}
        data = {}
        params = {}

        # Set the VDOM, if necessary
        if self.vdom:
            if self.vdom == 'global':
                pass
            else:
                params.update({'vdom': self.vdom})

        for inst_attr, fg_attr in self.data_attrs.items():
            if getattr(self, inst_attr): data.update({fg_attr: getattr(self, inst_attr)})

        # Add data and parameter dictionaries to conf dictionary
        conf.update({'data': data})
        conf.update({'parameters': params})

        return conf

    def get_api_config_update(self):
        # Need to set mkey to interface name when doing updates (puts) or deletes
        self.API_MKEY = self.obj_id

        conf = self.get_api_config_add()
        return conf

    def get_api_config_del(self):
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
        conf = self.get_api_config_del()
        return conf

    ##########################
    #   CLI Config Methods   #
    ##########################
    def get_cli_config_add(self):
        conf = ''

        # start vdom or global config
        if self.vdom:
            if self.vdom == 'global' and self.vdom_enabled:
                conf += "config global\n"
            else:
                conf += "config vdom\n"
                conf += " edit {} \n".format(self.vdom)

        # Config object's cli path
        conf += "{}\n".format(self.cli_path)

        # Edit obj_id
        conf += "  edit \"{}\" \n".format(self.obj_id)

        # For every attr defined in the data_attrs dictionary, if the dictionary value is true then add it to the
        # configuration.  Otherwise skip it.
        for inst_attr, fg_attr in self.data_attrs.items():

            # Check for cli attribute in ignore list and skip if contained
            if inst_attr in self.cli_ignore_attrs: continue

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
                            str_items += "{} ".format(str(item.get('name')))
                        else:
                            raise Exception("unrecognized key name for dictionary list: {}".format(item.keys()))

                conf += "    set {} {}\n".format(fg_attr, str_items)
            else:
                if getattr(self, inst_attr): conf += "    set {} {}\n".format(fg_attr, config_attr)

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
        conf = self.get_cli_config_add()
        return conf

    def get_cli_config_del(self):
        conf = ''
        if self.obj_id:

            # start vdom or global config
            if self.vdom:
                if self.vdom == 'global' and self.vdom_enabled:
                    conf += "config global\n"
            else:
                conf += "config vdom\n"
                conf += " edit {} \n".format(self.vdom)

            conf += "{}\n".format(self.cli_path)
            conf += "  delete {}\n".format(self.obj_id)
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
            raise Exception("\"obj_id\" must be set in order to configure it for delete")
