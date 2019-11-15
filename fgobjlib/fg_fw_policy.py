from fgobjlib import FgObject

class FgFwPolicy(FgObject):
    """
    FgFwPolicy class represents FortiGate Firewall policy object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications.

    Attributes:
        data_attrs (dict): Dictionary to define relevant config attributes and map instance attr names to fg attr names
        cli_ignore_attrs (list): List of attributes to ignore when generating CLI configurations
        policyid (int): Object ID
        srcintf (list):  Policy source interface(s), may be string or list of strings
        dstintf (list): Policy destination interface(s), may be string or list of strings
        srcaddr (list): Policy source address(es), may be string or list of strings
        dstaddr (list): Policy destination address(es), may be string or list of strings
        schedule (str): Policy schedule
        action (str):  Policy action, may be 'accept' or 'deny'
        logtraffic (str): Policy log action, may be 'utm', 'all' or 'disabled'
        nat (bool):  Source NAT for policy, True or False
        comment (str): Object comment
        vdom (str):  VDOM policy configured in  (if any)
    """

    def __init__(self, policyid: int = None, srcintf: list = None, dstintf: list = None, srcaddr: list = None,
                 dstaddr: list = None, service: list = None, schedule: str = None, action: str = None,
                 logtraffic: str = None, nat: bool = None, vdom: str = None, srcaddr_negate: bool = None,
                 dstaddr_negate: bool = None, name: str = None, comment: str = None, service_negate: bool = None):
        """
        Args:
            policyid (int): optional - ID of object.  Defines ID used in configs when API or CLI for config methods (default: 0)
            srcintf (list): required - string or list of strings referencing src interface(s) of policy
            dstintf (list): required - string or list of strings referencing dst interface(s) of policy
            srcaddr (list): required - string or list of strings referencing src address(s) of policy
            dstaddr (list): required - string or list of strings referencing dst address(s) of policy
            schedule (str): optional - string referencing schedule to associated with policy (default: 'always')
            action (str): optional - string sets action to assign to policy; may be 'accept' or 'deny' (default: deny)
            logtraffic (str): optional - string set logtraffic action to assign; may be utm/all/disabled (default: disabled)
            nat (bool): optional - string
            comment (str): optional - Set a comment up to 255 characters (default: None)
            vdom (str): optional - Set vdom.  If unset object configs uses default fg context (default: None)
        """


        # Initialize the parent class - we do set this here, because the subclass will first verify obj_id
        # is acceptable for this class type in the above attribute set functions
        super().__init__(api='cmdb', api_path='firewall', api_name='policy', cli_path="config firewall policy",
                         obj_id=policyid, vdom=vdom)

        ### Set parent class attributes ###
        # Map instance attribute names to fg attribute names
        self.data_attrs = {'policyid': 'policyid', 'srcintf': 'srcintf', 'dstintf': 'dstintf', 'srcaddr': 'srcaddr',
                           'service': 'service', 'schedule': 'schedule', 'action': 'action', 'logtraffic': 'logtraffic',
                           'nat': 'nat', 'srcaddr_negate': 'srcaddr-negate', 'dstaddr_negate': 'dstaddr-negate',
                           'service_negate': 'service-negate'}

        self.cli_ignore_attrs = ['policyid']

        # Set Instance Variables
        self.set_policyid(policyid)
        self.set_srcintf(srcintf)
        self.set_dstintf(dstintf)
        self.set_srcaddr(srcaddr)
        self.set_dstaddr(dstaddr)
        self.set_service(service)
        self.set_schedule(schedule)
        self.set_action(action)
        self.set_logtraffic(logtraffic)
        self.set_nat(nat)
        self.set_srcaddr_negate(srcaddr_negate)
        self.set_dstaddr_negate(dstaddr_negate)
        self.set_service_negate(service_negate)
        self.set_comment(comment)


    def set_policyid(self, policyid):
        """ Set self.policyid to policyid if policyid is valid or if not provided set policyid = 0.

        Args:
            policyid (int):  Integer representing ID of policy.

        Returns:
            None
        """
        if policyid:
            if isinstance(policyid, int):
                self.policyid = policyid
            else:
                raise Exception("If setting \"id\" it must be an integer")
        else:
            self.policyid = 0


    def set_srcintf(self, policy_object):
        """ Check the validity of srcintf objects and sets self.srcaddr to list containing objects of srcintf

        Args:
            policy_object (list): string or list of strings containing srcintf(s)

        Returns:
            None
        """

        if policy_object:
            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list

            obj_list = []

            if isinstance(policy_object, str):
                obj_list.append({'name': policy_object})

            elif isinstance(policy_object, list):
                for item in policy_object:
                    obj_list.append({'name': item})

            else:
                raise Exception("\"srcintf\", must be provided as string or list of strings")

            # Make sure each interface passed in is not all whitespace and it is less than 80 chars
            for item in obj_list:
                if isinstance(item['name'], str):
                    if item['name'].isspace(): raise Exception("{} cannot be an empty string".format(item))

                    if not len(item['name']) < 80:
                        raise Exception("\"srcintf(s)\", must be 79 chars or less")

                else:
                    raise Exception("\"srcintf\" must be string or list of strings")

            # set self.<obj_type> attribute with the verified and formatted obj_list
            self.srcintf = obj_list

        else:
            self.srcintf = None

    def set_dstintf(self, policy_object):
        """ Check the validity of dstintf objects and sets self.dstintf to list containing objects of dstintf

        Args:
            policy_object (list): string or list of strings containing dstintf(s)

        Returns:
            None
        """

        if policy_object:
            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list

            obj_list = []

            if isinstance(policy_object, str):
                obj_list.append({'name': policy_object})

            elif isinstance(policy_object, list):
                for item in policy_object:
                    obj_list.append({'name': item})

            else:
                raise Exception("\"dstintf\", must be provided as string or list of strings")

            # Make sure each interface passed in is not all whitespace and it is less than 80 chars
            for item in obj_list:
                if isinstance(item['name'], str):
                    if item['name'].isspace(): raise Exception("{} cannot be an empty string".format(item))

                    if not len(item['name']) < 80:
                        raise Exception("\"dstintf(s)\", must be 79 chars or less")

                else:
                    raise Exception("\"dstinf\", must be string or list of strings")

            # set self.<obj_type> attribute with the verified and formatted obj_list
            self.dstintf = obj_list

        else:
            self.dstintf = None

    def set_srcaddr(self, policy_object):
        """ Check the validity of srcaddr objects and sets self.srcaddr to list containing objects of srcaddr

        Args:
            policy_object (list): string or list of strings containing dstintf(s)

        Returns:
            None
        """

        if policy_object:
            # IF a single object was passed as a string, append it to obj_list else iterate the list and pull
            # out the strings of interfaces and append each to obj list

            obj_list = []

            if isinstance(policy_object, str):
                obj_list.append({'name': policy_object})

            elif isinstance(policy_object, list):
                for item in policy_object:
                    obj_list.append({'name': item})

            else:
                raise Exception("\"srcaddr\", must be provided as string or list of strings")

            # Make sure each interface passed in is not all whitespace and it is less than 80 chars
            for item in obj_list:
                if isinstance(item['name'], str):
                    if item['name'].isspace(): raise Exception("{} cannot be an empty string".format(item))

                    if not len(item['name']) < 80:
                        raise Exception("\"srcaddrs(s)\", must be 79 chars or less")

                else:
                    raise Exception("\"srcaddr\" must be string or list of strings")

            # set self.<obj_type> attribute with the verified and formatted obj_list
            self.srcaddr = obj_list

        else:
            self.srcaddr = None

    def set_dstaddr(self, policy_object):
        """ Check the validity of dstaddr objects and sets self.dstaddr to list containing objects of dstaddr

        Args:
            policy_object (list): string or list of strings containing dstintf(s)

        Returns:
            None
        """

        if policy_object:
            # IF a single object was passed as a string, append it to obj_list else iterate the list and pull
            # out the strings of interfaces and append each to obj list

            obj_list = []

            if isinstance(policy_object, str):
                obj_list.append({'name': policy_object})

            elif isinstance(policy_object, list):
                for item in policy_object:
                    obj_list.append({'name': item})

            else:
                raise Exception("\"dstaddr\",  must be provided as string or list of strings")

            # Make sure each interface passed in is not all whitespace and it is less than 80 chars
            for item in obj_list:
                if isinstance(item['name'], str):
                    if item['name'].isspace(): raise Exception("{} cannot be an empty string".format(item))

                    if not len(item['name']) < 80:
                        raise Exception("\"dstaddr(s)\", must be 79 chars or less")

                else:
                    raise Exception("\"dstaddr\" must be string or list of strings")

            # set self.<obj_type> attribute with the verified and formatted obj_list
            self.dstaddr = obj_list

        else:
            self.dstaddr = None

    def set_service(self, policy_object):
        """ Check the validity of service objects and sets self.service to list containing objects of service

        Args:
            policy_object (list): string or list of strings containing dstintf(s)

        Returns:
            None
        """

        if policy_object:
            # IF a single object was passed as a string, append it to obj_list else iterate the list and pull
            # out the strings of interfaces and append each to obj list

            obj_list = []

            if isinstance(policy_object, str):
                obj_list.append({'name': policy_object})

            elif isinstance(policy_object, list):
                for item in policy_object:
                    obj_list.append({'name': item})

            else:
                raise Exception("\"service\", must be provided as string or list of strings")

            # Make sure each interface passed in is not all whitespace and it is less than 80 chars
            for item in obj_list:
                if isinstance(item['name'], str):
                    if item['name'].isspace(): raise Exception("{} cannot be an empty string".format(item))

                    if not len(item['name']) < 80:
                        raise Exception("\"service(s)\", must be 79 chars or less")

                else:
                    raise Exception("\"service\" must be string or list of strings")

            # set self.<obj_type> attribute with the verified and formatted obj_list
            self.service = obj_list

        else:
            self.service = None

    def set_schedule(self, schedule):
        """ Set self.schedule to 'schedule' if 'schedule' name provided meets requirements

        Args:
            schedule (str): Policy schedule name

        Returns:
            None
        """
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
        """ Set self.action to 'action' if action meets requirements

        Args:
            action (str): policy action, may be 'accept' or 'deny'

        Returns:
            None
        """
        if action:
            if action.lower() == 'accept' or action.lower() == 'allow':
                self.action = 'accept'
            elif action.lower() == 'deny' or action.lower() == 'drop':
                self.action = 'deny'
            else:
                raise ValueError("\"action\", when set, must be either 'accept' or 'deny'")
        else:
            self.action = None

    def set_logtraffic(self, logtraffic):
        """ Set self.logtraffic to 'logtraffic' if logtraffic is valid

        Args:
            logtraffic (str): Policy log action.  May be 'utm', 'all' or 'disabled'

        Returns:
            None
        """
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

            elif logtraffic.lower() == 'disabled' or logtraffic.lower() == 'disable':
                self.logtraffic = 'disabled'
        else:
            self.logtraffic = None

    def set_nat(self, nat):
        """ Set self.nat to 'nat' if valid.  True=enable, False=disable

        Args:
            nat (bool): Policy source NAT, true (enable) or false (disable)

        Returns:
            None
        """
        if nat:
            if isinstance(nat, bool):
                self.nat = True
        else:
            self.nat = False

    def set_comment(self, comment):
        """ Set self.comment to 'comment' if comment string within requirements

        Args:
            comment (str):  Comment for this policy object

        Returns:
            None
        """
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

    def set_srcaddr_negate(self, negate):
        """ Set the self.srcaddr_negate attribute representing negate type in policy

        Args:
            negate (bool): True = (enable negating), False = (disable negating)

        Returns:
            None
        """
        if not negate is None:
            if isinstance(negate, bool):
                self.srcaddr_negate = 'enable' if negate == True else 'disable'
            else:
                raise ValueError("\"srcaddr_negate\", when set, must be type bool")
        else:
            self.srcaddr_negate = None

    def set_dstaddr_negate(self, negate):
        """ Set the self.dstaddr_negate attribute representing negate type in policy

        Args:
            negate (bool): True = (enable negating), False = (disable negating)

        Returns:
            None
        """
        if not negate is None:
            if isinstance(negate, bool):
                self.dstaddr_negate = 'enable' if negate == True else 'disable'
            else:
                raise ValueError("\"dstaddr_negate\", when set, must be type bool")
        else:
            self.dstaddr_negate = None

    def set_service_negate(self, negate):
        """ Set the self.service attribute representing negate type in policy

        Args:
            negate (bool): True = (enable negating), False = (disable negating)

        Returns:
            None
        """
        if not negate is None:
            if isinstance(negate, bool):
                self.service_negate = 'enable' if negate == True else 'disable'
            else:
                raise ValueError("\"service_negate\", when set, must be type bool")
        else:
            self.service_negate = None