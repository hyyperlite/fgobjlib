from fgobjlib import FgObject

class FgFwPolicy(FgObject):
    """
    FgFwPolicy class represents FortiGate Firewall policy object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications
    """

    def __init__(self, policyid: int = None, src_intf: list = None, dst_intf: list = None, src_addr: list = None,
                 dst_addr: list = None, service: list = None, schedule: list = None, action: str = None,
                 log_traffic: str = None, nat: bool = None, vdom: str = None, src_addr_negate: bool = None,
                 dst_addr_negate: bool = None, name: str = None, comment: str = None):

        # Initialize the parent class
        super().__init__(vdom=vdom, api='cmdb', api_path='firewall', api_name='policy', api_mkey=None)

        # Set Instance Variables
        self.set_policyid(policyid)
        self.src_intf = self.set_policy_objects(src_intf, 'src_intf')
        self.dst_intf = self.set_policy_objects(dst_intf, 'dst_intf')
        self.src_addr = self.set_policy_objects(src_addr, 'src_addr')
        self.dst_addr = self.set_policy_objects(dst_addr, 'dst_addr')
        self.service = self.set_policy_objects(service, 'service')
        self.set_schedule(schedule)
        self.set_action(action)
        self.set_logtraffic(log_traffic)
        self.set_nat(nat)
        self.set_vdom(vdom)
        self.src_addr_negate = self.set_negate(src_addr_negate)
        self.dst_addr_negate = self.set_negate(dst_addr_negate)
        self.set_name(name)
        self.set_comment(comment)

    def set_policyid(self, policyid):
        if policyid:
            if isinstance(policyid, int):
                self.policyid = policyid
            else:
                raise Exception("If setting \"id\" it must be an integer")
        else:
            self.policyid = 0


    @staticmethod
    def set_policy_objects(policy_object, obj_type):
        """ set_policy_objects: checks validity of src_intf, dst_intf, src_addr and dst_addr objects and returns a list
        of objects if they meet requirements otherwise raise an exception if requirements not met"""

        if policy_object:
            obj_list = []
            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list
            if isinstance(policy_object, str):
                obj_list.append({'name': policy_object})

            elif isinstance(policy_object, list):
                for item in policy_object:
                    obj_list.append({'name': item})

            else:
                raise Exception("{} must be provided as type string (with single {} referenced or as a list "
                                "for multiple {} references".format(obj_type, obj_type, obj_type))

            # Make sure each interface passed in is not all whitespace and it is less than 80 chars
            for item in obj_list:
                if isinstance(item['name'], str):
                    if item['name'].isspace(): raise Exception("{} cannot be an empty string".format(item))

                    if not len(item['name']) < 80:
                        raise Exception("{}, must be less 79 chars or less".format(obj_type))

                else:
                    raise Exception("{}, must be type str or a list (array) of strings".format(obj_type))
            return obj_list

        else:
            raise Exception("{} is required but was not provided".format(type))

    def set_schedule(self, schedule):
        if schedule:
            if isinstance(schedule, str):
                if not len(schedule) <= 36:
                    raise Exception("\"schedule\", when set, must be less 35 chars or less")

                if schedule.isspace():
                    raise Exception("\"schedule\", when set, cannot be an empty string")
            else:
                raise Exception("\"schedule\", when set, must be type str")

            self.schedule = schedule
        else:
            self.schedule = 'always'

    def set_action(self, action):
        if action:
            if action.lower() == 'accept' or action.lower() == 'allow':
                self.action = 'accept'
        else:
            self.action = None

    def set_logtraffic(self, logtraffic):
        if logtraffic:
            if logtraffic.lower() == 'utm':

                # can't log utm if policy action is not accept
                if self.action == 'accept':
                    self.log_traffic = 'utm'
                else:
                    raise Exception("Cannot set \"logtraffic\" to utm when policy action is deny (deny "
                                    "is default policy action")

            elif logtraffic.lower() == 'all':
                self.log_traffic = 'all'

            elif logtraffic.lower() == 'disabled':
                self.log_traffic = 'disabled'
        else:
            self.log_traffic = None

    def set_nat(self, nat):
        if nat:
            if isinstance(nat, bool):
                self.nat = True
        else:
            self.nat = False

    def set_name(self, name):
        if name:
            if isinstance(name, str):
                if 1 <= len(name) <= 35:
                    self.name = name
                else:
                    raise Exception("\"name\", when set, must be type str between 1 and 35 chars")
            else:
                raise Exception("\"name\", when set, must be type str")
        else:
            self.name = None

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

    @staticmethod
    def set_negate(negate):
        if negate and isinstance(negate, bool):
            return True
        else:
            return False

    def get_cli_config_add(self):
        conf = ''

        # Set config parameters where needed
        if self.vdom: conf += "config vdom\n edit {} \n".format(self.vdom)

        conf += "config firewall policy\n  edit \"{}\" \n".format(self.policyid)

        if self.src_intf: conf += "    set srcintf {} \n".format(' '.join(self.src_intf))
        if self.dst_intf: conf += "    set dstintf {} \n".format(' '.join(self.dst_intf))
        if self.src_addr: conf += "    set srcaddr {} \n".format(' '.join(self.src_addr))
        if self.dst_addr: conf += "    set dstaddr {} \n".format(' '.join(self.dst_addr))
        if self.service: conf += "    set service {} \n".format(' '.join(self.service))
        if self.schedule: conf += "    set schedule {} \n".format(self.schedule)
        if self.action: conf += "    set action {} \n".format(self.action)
        if self.log_traffic: conf += "    set logtraffic {} \n".format(self.log_traffic)
        if self.nat: conf += "    set nat enable \n"
        if self.src_addr_negate: conf += "    set srcaddr-negate enable \n"
        if self.dst_addr_negate: conf += "    set dstaddr-negate enable \n"
        if self.name: conf += "    set name {} \n".format(self.name)
        if self.comment: conf += "    set comments \"{}\" \n".format(self.comment)

        conf += "end\n"
        if self.vdom: conf += "end\n"
        return conf

    def get_cli_config_update(self):
        conf = self.get_cli_config_add()
        return conf

    def get_api_config_add(self):
        conf = {'api': self.API, 'path': self.API_PATH, 'name': self.API_NAME, 'mkey': self.API_MKEY, 'action': None}
        data = {}
        params = {}

        # Set the VDOM, if necessary
        if self.vdom:
            params.update({'vdom': self.vdom})
            data.update({'vdom': self.vdom})

        if self.policyid: data.update({'policyid': self.policyid})
        if self.src_intf: data.update({'srcintf': self.src_intf})
        if self.dst_intf: data.update({'dstintf': self.dst_intf})
        if self.src_addr: data.update({'srcaddr': self.src_addr})
        if self.dst_addr: data.update({'dstaddr': self.dst_addr})
        if self.service: data.update({'service': self.service})
        if self.schedule: data.update({'schedule': self.schedule})
        if self.action: data.update({'action': self.action})
        if self.log_traffic: data.update({'logtraffic': self.log_traffic})
        if self.nat: data.update({'nat': self.nat})
        if self.src_addr_negate: data.update({'srcaddr-negate': self.src_addr_negate})
        if self.dst_addr_negate: data.update({'dstaddr-negate': self.dst_addr_negate})
        if self.name: data.update({'name': self.name})
        if self.comment: data.update({'comments': self.comment})

        conf.update({'data': data})
        conf.update({'parameters': params})

        return conf

    def get_api_config_update(self):
        # Need to set mkey to interfac name when doing updates (puts) or deletes
        self.API_MKEY = self.policyid

        conf = self.get_api_config_add()
        return conf

    def get_cli_config_del(self):
        conf = ''
        if self.policyid:
            if self.vdom: conf += "config vdom\nedit {}\n".format(self.vdom)
            conf += "config system interface\n"
            conf += "delete {}\n".format(self.policyid)
            conf += "end\n"
            if self.vdom: conf += "end\n"
            return conf
        else:
            raise Exception("Policy id must be set in order to configure it for delete")

    def get_api_config_del(self):
        conf = {'api': self.API, 'path': self.API_PATH, 'name': self.API_NAME, 'mkey': self.API_MKEY, 'action': None}
        data = {}
        params = {}

        # Set the VDOM, if necessary
        if self.vdom:
            params.update({'vdom': self.vdom})
            data.update({'vdom': self.vdom})

        if self.policyid:
            # Set the mkey value to interface name and updated other vars
            conf['mkey'] = self.policyid
            conf.update({'data': data})
            conf.update({'parameters': params})

        else:
            raise Exception("policy \"id\" must be set in order get or delete an existing policy")

        return conf

    def get_api_config_get(self):
        conf = self.get_api_config_del()
        return conf