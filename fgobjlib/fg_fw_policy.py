from typing import Union

from fgobjlib import FgObject


class FgFwPolicy(FgObject):
    """
    FgFwPolicy class represents FortiGate Firewall policy object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications.

    Attributes:
        policyid (int): Object ID
        srcintf (list):  Policy source interface(s), may be string or list of strings
        dstintf (list): Policy destination interface(s), may be string or list of strings
        srcaddr (list): Policy source address(es), may be string or list of strings
        dstaddr (list): Policy destination address(es), may be string or list of strings
        schedule (str): Policy schedule
        action (str):  Policy action, may be 'accept' or 'deny'
        logtraffic (str): Policy log action, may be 'utm', 'all' or 'disabled'
        nat (str):  Source NAT for policy.  ('enable', 'disable', or None=inherit)
        comment (str): Object comment
        vdom (str):  VDOM policy configured in  (if any)
        srcaddr_negate (str): Negate the source address in policy.  ('enable', 'disable', or None=inherit)
        dstaddr_negate (str): Negate the destination address in policy.  ('enable', 'disable', or None=inherit)
        service (str): Negate the service in policy.  ('enable', 'disable', or None=inherit)
    """

    def __init__(self, policyid: int = None, srcintf: Union[str, list] = None, dstintf: Union[str, list] = None,
                 srcaddr: Union[str, list] = None, dstaddr: Union[str, list] = None, service: Union[str, list] = None,
                 schedule: str = None, action: str = None, logtraffic: str = None, nat: str = None, vdom: str = None,
                 srcaddr_negate: str = None, dstaddr_negate: str = None, name: str = None, comment: str = None,
                 service_negate: str = None):
        """
        Args:
            policyid (int): ID of object.  Defines ID used in configs when API or CLI for config methods (default: 0)
            srcintf (list): string or list of strings referencing src interface(s) of policy
            dstintf (list): string or list of strings referencing dst interface(s) of policy
            srcaddr (list): string or list of strings referencing src address(s) of policy
            dstaddr (list): string or list of strings referencing dst address(s) of policy
            schedule (str): string referencing schedule to associated with policy (default: 'always')
            action (str): string sets action to assign to policy; may be 'accept' or 'deny' (default: deny)
            logtraffic (str): string set logtraffic action to assign; may be utm/all/disabled (default: disabled)
            nat (str): set nat enabled or disable ('enable', 'disable', or None=inherit)
            comment (str): set a comment up to 255 characters (default: None)
            vdom (str): opt - set vdom.  If unset object configs uses default fg context (default: None)
            srcaddr_negate (str): Negate the source address in policy.  ('enable', 'disable', or None=inherit)
            dstaddr_negate (str): Negate the destination address in policy.  ('enable', 'disable', or None=inherit)
            service (str): Negate the service in policy.  ('enable', 'disable', or None=inherit)
        """

        # Initialize the parent class - we do set this here, because the subclass will first verify obj_id
        # is acceptable for this class type in the above attribute set functions
        super().__init__(api='cmdb', api_path='firewall', api_name='policy', cli_path="config firewall policy",
                         obj_id=policyid, vdom=vdom)

        # Set parent class attributes
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'policyid': 'policyid', 'srcintf': 'srcintf', 'dstintf': 'dstintf', 'srcaddr': 'srcaddr',
                            'dstaddr': 'dstaddr', 'service': 'service', 'schedule': 'schedule', 'action': 'action',
                            'logtraffic': 'logtraffic', 'nat': 'nat', 'srcaddr_negate': 'srcaddr-negate',
                            'dstaddr_negate': 'dstaddr-negate', 'service_negate': 'service-negate', 'name': 'name'}

        self._cli_ignore_attrs = ['policyid']

        # Set Instance Variables (uses @property and setters defined below)
        self.policyid = policyid
        self.srcintf = srcintf
        self.dstintf = dstintf
        self.srcaddr = srcaddr
        self.dstaddr = dstaddr
        self.service = service
        self.schedule = schedule
        self.action = action
        self.logtraffic = logtraffic
        self.nat = nat
        self.srcaddr_negate = srcaddr_negate
        self.dstaddr_negate = dstaddr_negate
        self.service_negate = service_negate
        self.comment = comment
        self.name = name

        # Update the parent defined obj_to_str attribute with this objects str representation
        self._obj_to_str += f', policyid={self.policyid}, srcintf={self.srcintf}, dstintf={self.dstintf}, ' \
                            f'srcaddr={self.srcaddr}, dstaddr={self.dstaddr}, service={self.service}, ' \
                            f'schedule={self.schedule}, action={self.action}, logtraffic={self.logtraffic}, ' \
                            f'nat={self.nat}, srcaddr_negate={self.srcaddr_negate}, ' \
                            f'dstaddr_negate={self.dstaddr_negate}, service_negate={self.service_negate}, ' \
                            f'comment={self.comment}, vdom={self.vdom}'

    # Static Methods
    @staticmethod
    def _validate_and_get_policy_obj(policy_object):
        """ Check the validity of policy objects and returns objects as list if valid

        Can be used to validate srcintf, dstintf, srcaddr, dstaddr and service objects

        Args:
            policy_object (list): string or list of strings containing srcintf(s)

        Returns:
            List
        """

        if policy_object is None:
            return policy_object

        else:
            # IF a single object was passed as a string, append it to intf_list else iterate the list and pull
            # out the strings of interfaces and append each to intf_list
            obj_list = []

            if isinstance(policy_object, str):
                obj_list.append({'name': policy_object})

            elif isinstance(policy_object, list):
                for item in policy_object:
                    obj_list.append({'name': item})

            else:
                raise Exception("'policy_object(s)', must be provided as string or list of strings")

            # Make sure each interface passed in is not all whitespace and it is less than 80 chars
            for item in obj_list:
                if isinstance(item['name'], str):
                    if item['name'].isspace():
                        raise Exception(f"{item} cannot be an empty string")

                    if not len(item['name']) < 80:
                        raise Exception("'policy_object(s)', must be 79 chars or less")

                else:
                    raise Exception("'policy_objects(s)' must be string or list of strings")

            # set self.<obj_type> attribute with the verified and formatted obj_list
            return obj_list

    # Instance Properties and Setters
    @property
    def policyid(self):
        return self._policyid

    @policyid.setter
    def policyid(self, policyid):
        """ Set self.policyid to policyid if policyid is valid or if not provided set policyid = 0.

        Args:
            policyid (int):  Integer representing ID of policy.

        Returns:
            None
        """
        if policyid is None:
            self._policyid = 0

        else:
            if isinstance(policyid, int):
                self._policyid = policyid
            else:
                raise Exception("'id', when set, must be an integer")

    @property
    def srcintf(self):
        return self._srcintf

    @srcintf.setter
    def srcintf(self, policy_object):
        """ Check the validity of srcintf objects and sets self.srcintf to list containing objects of dstintf

        Calls _validate_and_get_policy_obj()

        Args:
            policy_object (list): string or list of strings containing srcintfs(s)

        Returns:
            None
        """
        self._srcintf = self._validate_and_get_policy_obj(policy_object)

    @property
    def dstintf(self):
        return self._dstintf

    @dstintf.setter
    def dstintf(self, policy_object):
        """ Check the validity of dstintf objects and sets self.dstintf to list containing objects of dstintf

        Calls _validate_and_get_policy_obj()

        Args:
            policy_object (list): string or list of strings containing dstintf(s)

        Returns:
            None
        """
        self._dstintf = self._validate_and_get_policy_obj(policy_object)

    @property
    def srcaddr(self):
        return self._srcaddr

    @srcaddr.setter
    def srcaddr(self, policy_object):
        """ Check the validity of srcaddr objects and sets self.srcaddr to list containing objects of srcaddr

        Calls _validate_and_get_policy_obj()

        Args:
            policy_object (list): string or list of strings containing dstintf(s)

        Returns:
            None
        """
        self._srcaddr = self._validate_and_get_policy_obj(policy_object)

    @property
    def dstaddr(self):
        return self._dstaddr

    @dstaddr.setter
    def dstaddr(self, policy_object):
        """ Check the validity of dstaddr objects and sets self.dstaddr to list containing objects of dstaddr

        Calls _validate_and_get_policy_obj()

        Args:
            policy_object (list): string or list of strings containing dstintf(s)

        Returns:
            None
        """
        self._dstaddr = self._validate_and_get_policy_obj(policy_object)

    @property
    def service(self):
        return self._service

    @service.setter
    def service(self, policy_object):
        """ Check the validity of service objects and sets self.service to list containing objects of service

        Calls _validate_and_get_policy_obj()

        Args:
            policy_object (list): string or list of strings containing dstintf(s)

        Returns:
            None
        """
        self._service = self._validate_and_get_policy_obj(policy_object)

    @property
    def schedule(self):
        return self._schedule

    @schedule.setter
    def schedule(self, schedule):
        """ Set self.schedule to 'schedule' if 'schedule' name provided meets requirements

        Args:
            schedule (str): Policy schedule name

        Returns:
            None
        """
        if schedule is None:
            self._schedule = None

        else:
            if isinstance(schedule, str):
                if not len(schedule) <= 35:
                    raise ValueError("'schedule, when set, must be type str() 35 chars or less")

                if schedule.isspace():
                    raise ValueError("'schedule', when set, cannot be an empty string")
            else:
                raise ValueError("'schedule', when set, must be type str() 35 chars or less")

            self._schedule = schedule

    @property
    def action(self):
        return self._action

    @action.setter
    def action(self, action):
        """ Set self.action to 'action' if action meets requirements

        Args:
            action (str): policy action, may be 'accept' or 'deny'

        Returns:
            None
        """
        if action is None:
            self._action = None

        elif isinstance(action, str):
            if action.lower() == 'accept' or action.lower() == 'allow':
                self._action = 'accept'
            elif action.lower() == 'deny' or action.lower() == 'drop':
                self._action = 'deny'
            else:
                raise ValueError("'action', when set, must be type str() with value 'accept' or 'deny'")
        else:
            raise ValueError("'action', when set, must be type str() with value 'accept' or 'deny'")

    @property
    def logtraffic(self):
        return self._logtraffic

    @logtraffic.setter
    def logtraffic(self, logtraffic):
        """ Set self.logtraffic to 'logtraffic' if logtraffic is valid

        Args:
            logtraffic (str): Policy log action.  May be 'utm', 'all' or 'disabled'

        Returns:
            None
        """
        if logtraffic is None:
            self._logtraffic = None

        elif isinstance(logtraffic, str):
            if logtraffic.lower() == 'utm':
                self._logtraffic = 'utm'

            elif logtraffic.lower() == 'all':
                self._logtraffic = 'all'

            elif logtraffic.lower() == 'disabled' or logtraffic.lower() == 'disable':
                self._logtraffic = 'disabled'
            else:
                raise ValueError("'logtraffic', when set must be type str() with value 'utm', 'all' or 'disabled'")
        else:
            raise ValueError("'logtraffic', when set must be type str()")

    @property
    def nat(self):
        return self._nat

    @nat.setter
    def nat(self, nat):
        """ Set self.nat to 'nat' if valid.  True=enable, False=disable

        Args:
            nat (str): Policy source NAT. ('enable', 'disable', or None=inherit)

        Returns:
            None
        """
        if nat is None:
            self._nat = None

        else:
            if isinstance(nat, str):
                if nat == 'enable':
                    self._nat = 'enable'
                elif nat == 'disable':
                    self._nat = 'disable'
                else:
                    raise ValueError("'nat', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'nat', when set, must be type str()")

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, comment):
        """ Set self.comment to 'comment' if comment string within requirements

        Args:
            comment (str):  Comment for this policy object

        Returns:
            None
        """
        if comment is None:
            self._comment = None

        else:
            if isinstance(comment, str):
                if 1 <= len(comment) <= 1023:
                    self._comment = comment
                else:
                    raise ValueError("'comment', when set, must be type str() between 1 and 1023 chars")
            else:
                raise ValueError("'comment', when set, must be type str()")

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        """ Set self.comment to 'comment' if comment string within requirements

        Args:
            name (str):  Optional Name for this policy object

        Returns:
            None
        """
        if name is None:
            self._name = None

        else:
            if isinstance(name, str):
                if 1 <= len(name) <= 35:
                    self._name = name
                else:
                    raise ValueError("'name', when set, must be type str() between 1 and 1,023 chars")
            else:
                raise ValueError("'name', when set, must be type str()")

    @property
    def srcaddr_negate(self):
        return self._srcaddr_negate

    @srcaddr_negate.setter
    def srcaddr_negate(self, negate):
        """ Set the self.srcaddr_negate attribute representing negate type in policy

        Args:
            negate (str): ('enable', 'disable', or None=inherit)

        Returns:
            None
        """
        if negate is None:
            self._srcaddr_negate = None

        else:
            if isinstance(negate, str):
                if negate == 'enable':
                    self._srcaddr_negate = 'enable'
                elif negate == 'disable':
                    self._srcaddr_negate = 'disable'
                else:
                    raise ValueError("'srcaddr_negate, when set, must be type str() with value 'enable' or 'disable")
            else:
                raise ValueError("'srcaddr_negate', when set, must be type str()")

    @property
    def dstaddr_negate(self):
        return self._dstaddr_negate

    @dstaddr_negate.setter
    def dstaddr_negate(self, negate):
        """ Set the self.dstaddr_negate attribute representing negate type in policy

        Args:
            negate (str): ('enable', 'disable', or None=inherit)

        Returns:
            None
        """
        if negate is None:
            self._dstaddr_negate = None

        else:
            if isinstance(negate, str):
                if negate == 'enable':
                    self._dstaddr_negate = 'enable'
                elif negate == 'disable':
                    self._dstaddr_negate = 'disable'
                else:
                    raise ValueError("'dstaddr_negate', when set, must be type str() with value 'enable' or 'disable'")

            else:
                raise ValueError("'dstaddr_negate', when set, must be type str()")

    @property
    def service_negate(self):
        return self._service_negate

    @service_negate.setter
    def service_negate(self, negate):
        """ Set the self.service attribute representing negate type in policy

        Args:
            negate (str): ('enable', 'disable', or None=inherit)

        Returns:
            None
        """
        if negate is None:
            self._service_negate = None

        else:
            if isinstance(negate, str):
                if negate == 'enable':
                    self._service_negate = 'enable'
                elif negate == 'disable':
                    self._service_negate = 'disable'
                else:
                    raise ValueError("'service_negate', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'service_negate', when set, must be type str()")
