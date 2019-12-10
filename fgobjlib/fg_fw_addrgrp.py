from typing import Union

from fgobjlib import FgObject


class FgFwAddressGroup(FgObject):
    """
    FgFwAddressGroup class represents FortiGate Firewall firewall address group object and provides methods for
    validating parameters and generating both cli and api configuration data for use in external configuration
    applications.

    Attributes:
        name (str): Name of addrgrp to be created
        member (list): List of member fw addresses to include in group
        exclude (str): Set exclude addresses from addrgrp 'enable' or 'disable'
        exclude_member (list): The members to exclude from addrgrp
        comment (str):  Comment for addrgrp
        visibility (str): Set gui visibility 'enable' or 'disable'
        allow_routing (str): Set allow addrgrp use in static routing configuration 'enable' or 'disable'
    """

    def __init__(self, name: str = None, member: Union[str, list] = None, exclude: str = None,
                 exclude_member: Union[str, list] = None, comment: str = None, visibility: str = None,
                 allow_routing: str = None, vdom: str = None):
        """
        Args:
            name (str): Name of addrgrp to be created
            member (list): List of member fw addresses to include in group
            exclude (str): Set exclude addresses from addrgrp 'enable' or 'disable'
            exclude_member (list): The members to exclude from addrgrp
            comment (str):  Comment for addrgrp
            visibility (str): Set gui visibility 'enable' or 'disable'
            allow_routing (str): Set allow addrgrp use in static routing configuration 'enable' or 'disable'
        """

        # Initialize the parent class - we do set this here, because the subclass will first verify obj_id
        # is acceptable for this class type in the above attribute set functions
        super().__init__(api='cmdb', api_path='firewall', api_name='addrgrp', cli_path="config firewall addrgrp",
                         obj_id=name, vdom=vdom)

        # Set parent class attributes
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'name': 'name', 'member': 'member', 'exclude': 'exclude',
                            'exclude_member': 'exclude-member', 'comment': 'comment', 'visibility': 'visibility',
                            'allow_routing': 'allow-routing'}

        self._cli_ignore_attrs = []

        # Set Instance Variables (uses @property and setters defined below)
        self.name = name
        self.member = member
        self.exclude = exclude
        self.exclude_member = exclude_member
        self.visibility = visibility
        self.allow_routing = allow_routing
        self.comment = comment

        # Update the parent defined obj_to_str attribute with this objects str representation
        self._obj_to_str += f', name={self.name}, member={self.member}, exclude={self.exclude}, ' \
                            f'exclude_member={self.exclude_member}, visibility={self.visibility}, ' \
                            f'allow_routing={self.allow_routing}, comment={self.comment}'

    # Static Methods
    @staticmethod
    def _validate_and_get_members(members):
        """ Check the validity of policy objects and returns objects as list if valid

        Can be used to validate srcintf, dstintf, srcaddr, dstaddr and service objects

        Args:
            members (list): string or list of strings containing fw address objs as members

        Returns:
            List
        """

        if members is None:
            return None
        else:
            # IF a single object was passed as a string, append it to member_list else iterate the list and pull
            # out the strings of members and append each to member_list
            member_list = []

            if isinstance(members, str):
                member_list.append({'name': members})

            elif isinstance(members, list):
                for item in members:
                    member_list.append({'name': item})

            else:
                raise Exception("'members', must be provided as string or list of strings")

            # Make sure each interface passed in is not all whitespace and it is less than 80 chars
            for item in member_list:
                if isinstance(item['name'], str):
                    if item['name'].isspace():
                        raise Exception("members cannot be an contain values that are an empty string")

                    if not len(item['name']) < 80:
                        raise Exception("'policy_object(s)', must be 79 chars or less")

                else:
                    raise Exception("'policy_objects(s)' must be string or list of strings")

            # set self.<obj_type> attribute with the verified and formatted obj_list
            return member_list

    # Instance Properties and Setters
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
                if 1 <= len(name) <= 79:
                    self._name = name
                else:
                    raise ValueError("'name', when set, must be type str() between 1 and 79 chars")
            else:
                raise ValueError("'name', when set, must be type str()")

    @property
    def member(self):
        return self._member

    @member.setter
    def member(self, member):
        """ Check the validity of members list

        Calls _validate_and_get_members()

        Args:
            member(list): string or list of strings containing member fw address object names

        Returns:
            None
        """
        self._member = self._validate_and_get_members(member)

    @property
    def exclude_member(self):
        return self._exclude_member

    @exclude_member.setter
    def exclude_member(self, exclude_member):
        """ Check the validity of members list

        Calls _validate_and_get_members()

        Args:
            exclude_member (list): string or list of strings containing member fw address object names

        Returns:
            None
        """
        self._exclude_member = self._validate_and_get_members(exclude_member)

    @property
    def visibility(self):
        return self._visibility

    @visibility.setter
    def visibility(self, visibility):
        """ Set self.visibility if valid.  allowed values: 'enable' or 'disable'

        Args:
            visibility (str): addrgrp visibility. ('enable', 'disable', or None=inherit)

        Returns:
            None
        """
        if visibility is None:
            self._visibility = None

        else:
            if isinstance(visibility, str):
                if visibility == 'enable':
                    self._visibility = 'enable'
                elif visibility == 'disable':
                    self._visibility = 'disable'
                else:
                    raise ValueError("'visibility', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'visibility', when set, must be type str()")

    @property
    def allow_routing(self):
        return self._allow_routing

    @allow_routing.setter
    def allow_routing(self, allow_routing):
        """ Set self.allow_routing  if valid.  allowed values: 'enable' or 'disable'

        Args:
            allow_routing (str): allow object in routing config. ('enable', 'disable', or None=inherit)

        Returns:
            None
        """
        if allow_routing is None:
            self._allow_routing = None

        else:
            if isinstance(allow_routing, str):
                if allow_routing == 'enable':
                    self._allow_routing = 'enable'
                elif allow_routing == 'disable':
                    self._allow_routing = 'disable'
                else:
                    raise ValueError("'allow_routing', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'allow_routing', when set, must be type str()")

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
                if 1 <= len(comment) <= 255:
                    self._comment = comment
                else:
                    raise ValueError("'comment', when set, must be type str() between 1 and 255 chars")
            else:
                raise ValueError("'comment', when set, must be type str()")
