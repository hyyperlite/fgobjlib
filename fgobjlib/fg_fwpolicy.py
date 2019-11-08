from fgobjlib import FgObject

class FgFwPolicy(FgObject):
    """
    FgFwPolicy class represents FortiGate Firewall policy object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications
    """

    def __init__(self, policyid: int = None, srcintf: list = None, dstintf: list = None, srcaddr: list = None,
                 dstaddr: list = None, service: list = None, schedule: list = None, action: str = None,
                 logtraffic: str = None, nat: bool = None, vdom: str = None, srcaddr_negate: bool = None,
                 dstaddr_negate: bool = None, name: str = None, comment: str = None):

        # Set Instance Variables
        self.set_policyid(policyid)
        self.srcintf = self.set_policy_objects(srcintf, 'srcintf')
        self.dstintf = self.set_policy_objects(dstintf, 'dstintf')
        self.srcaddr = self.set_policy_objects(srcaddr, 'srcaddr')
        self.dstaddr = self.set_policy_objects(dstaddr, 'dstaddr')
        self.service = self.set_policy_objects(service, 'service')
        self.set_schedule(schedule)
        self.set_action(action)
        self.set_logtraffic(logtraffic)
        self.set_nat(nat)
        self.srcaddr_negate = self.set_negate(srcaddr_negate)
        self.dstaddr_negate = self.set_negate(dstaddr_negate)
        self.set_name(name)
        self.set_comment(comment)

        # Initialize the parent class - we do set this here, because the subclass will first verify obj_id
        # is acceptable for this class type in the above attribute set functions
        super().__init__(vdom=vdom, api='cmdb', api_path='firewall', api_name='policy', api_mkey=None,
                         obj_id=self.policyid)

        ### Set parent class attributes ###
        # CLI config path for this object type
        self.cli_path = "config firewall policy"

        # Map instance attribute names to fg attribute names
        self.data_attrs = {'policyid': 'policyid', 'srcintf': 'srcintf', 'dstintf': 'dstintf', 'srcaddr': 'srcaddr',
                           'service': 'service', 'schedule': 'schedule', 'action': 'action', 'logtraffic': 'logtraffic',
                           'nat': 'nat', 'srcaddr_negate': 'srcaddr-negate', 'dstaddr_negate': 'dstaddr-negate'}

        self.cli_ignore_attrs = ['policyid']

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
        """
        set_policy_objects: checks validity of srcintf, dstintf, srcaddr and dstaddr objects and returns a list
        of objects if they meet requirements otherwise raise an exception if requirements not met
        """

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
                    self.logtraffic = 'utm'
                else:
                    raise Exception("Cannot set \"logtraffic\" to utm when policy action is deny (deny "
                                    "is default policy action")

            elif logtraffic.lower() == 'all':
                self.logtraffic = 'all'

            elif logtraffic.lower() == 'disabled':
                self.logtraffic = 'disabled'
        else:
            self.logtraffic = None

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

    # def get_cli_config_add(self):
    #     conf = ''
    #
    #     # Set config parameters where needed
    #     if self.vdom: conf += "config vdom\n edit {} \n".format(self.vdom)
    #
    #     conf += "config firewall policy\n  edit \"{}\" \n".format(self.policyid)
    #
    #     if self.srcsintf: conf += "    set srcintf {} \n".format(' '.join(self.srcintf))
    #     if self.dstintf: conf += "    set dstintf {} \n".format(' '.join(self.dstintf))
    #     if self.srcaddr: conf += "    set srcaddr {} \n".format(' '.join(self.srcaddr))
    #     if self.dstaddr: conf += "    set dstaddr {} \n".format(' '.join(self.dstaddr))
    #     if self.service: conf += "    set service {} \n".format(' '.join(self.service))
    #     if self.schedule: conf += "    set schedule {} \n".format(self.schedule)
    #     if self.action: conf += "    set action {} \n".format(self.action)
    #     if self.log_traffic: conf += "    set logtraffic {} \n".format(self.log_traffic)
    #     if self.nat: conf += "    set nat enable \n"
    #     if self.srcaddr_negate: conf += "    set srcaddr-negate enable \n"
    #     if self.dstaddr_negate: conf += "    set dstaddr-negate enable \n"
    #     if self.name: conf += "    set name {} \n".format(self.name)
    #     if self.comment: conf += "    set comments \"{}\" \n".format(self.comment)
    #
    #     conf += "end\n"
    #     if self.vdom: conf += "end\n"
    #     return conf
    #
    # def get_cli_config_update(self):
    #     conf = self.get_cli_config_add()
    #     return conf
    #
    # def get_api_config_add(self):
    #     conf = {'api': self.API, 'path': self.API_PATH, 'name': self.API_NAME, 'mkey': self.API_MKEY, 'action': None}
    #     data = {}
    #     params = {}
    #
    #     # Set the VDOM, if necessary
    #     if self.vdom:
    #         params.update({'vdom': self.vdom})
    #         data.update({'vdom': self.vdom})
    #
    #     if self.policyid: data.update({'policyid': self.policyid})
    #     if self.srcintf: data.update({'srcintf': self.srcintf})
    #     if self.dstintf: data.update({'dstintf': self.dstintf})
    #     if self.srcaddr: data.update({'srcaddr': self.srcaddr})
    #     if self.dstaddr: data.update({'dstaddr': self.dstaddr})
    #     if self.service: data.update({'service': self.service})
    #     if self.schedule: data.update({'schedule': self.schedule})
    #     if self.action: data.update({'action': self.action})
    #     if self.log_traffic: data.update({'logtraffic': self.log_traffic})
    #     if self.nat: data.update({'nat': self.nat})
    #     if self.srcaddr_negate: data.update({'srcaddr-negate': self.srcaddr_negate})
    #     if self.dstaddr_negate: data.update({'dstaddr-negate': self.dstaddr_negate})
    #     if self.name: data.update({'name': self.name})
    #     if self.comment: data.update({'comments': self.comment})
    #
    #     conf.update({'data': data})
    #     conf.update({'parameters': params})
    #
    #     return conf
    #
    # def get_api_config_update(self):
    #     # Need to set mkey to interfac name when doing updates (puts) or deletes
    #     self.API_MKEY = self.policyid
    #
    #     conf = self.get_api_config_add()
    #     return conf
    #
    # def get_cli_config_del(self):
    #     conf = ''
    #     if self.policyid:
    #         if self.vdom: conf += "config vdom\nedit {}\n".format(self.vdom)
    #         conf += "config system interface\n"
    #         conf += "delete {}\n".format(self.policyid)
    #         conf += "end\n"
    #         if self.vdom: conf += "end\n"
    #         return conf
    #     else:
    #         raise Exception("Policy id must be set in order to configure it for delete")
    #
    # def get_api_config_del(self):
    #     conf = {'api': self.API, 'path': self.API_PATH, 'name': self.API_NAME, 'mkey': self.API_MKEY, 'action': None}
    #     data = {}
    #     params = {}
    #
    #     # Set the VDOM, if necessary
    #     if self.vdom:
    #         params.update({'vdom': self.vdom})
    #         data.update({'vdom': self.vdom})
    #
    #     if self.policyid:
    #         # Set the mkey value to interface name and updated other vars
    #         conf['mkey'] = self.policyid
    #         conf.update({'data': data})
    #         conf.update({'parameters': params})
    #
    #     else:
    #         raise Exception("policy \"id\" must be set in order get or delete an existing policy")
    #
    #     return conf
    #
    # def get_api_config_get(self):
    #     conf = self.get_api_config_del()
    #     return conf