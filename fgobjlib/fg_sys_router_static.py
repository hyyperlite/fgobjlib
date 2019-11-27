from fgobjlib import FgObject
import ipaddress


class FgRouteIPv4(FgObject):
    """FgRouteIPv4 class represents FortiGate Firewall static route object and provides methods for validating
    parameters and generating both cli and api configuration data for use in external configuration applications

    Attributes:
        routeid (str): ID of this object.
        dst (str): Destination Network, an IPv4 Network
        device (str): Destination interface
        gateway (str): Next-hop gateway, an IPv4 Address
        distance (int): Route distance
        priority (int): Route priority
        weight (int): Route weight
        comment (str): Route comment
        blackhole (str): Blackhole route ('enable', 'disable', or None=inherit)
        vrf (int): vrf ID for route
        vdom (str): vdom for this route
    """

    def __init__(self, routeid: int = None, dst: str = None, device: str = None, gateway: str = None,
                 distance: int = None, priority: int = None, weight: int = None, comment: str = None,
                 blackhole: str = None, vrf: int = None, vdom: str = None):
        """
        Args:
            routeid (int): ID for route object.  If not set, defaults to 0.
            dst (str): Destination network for route.  Must be valid IPv4 network/mask.  If no mask, defaults to /32.
            device (str): Destination interface for route.
            gateway (str): Next-hop gateway for route.  Must be valid IPv4 address.
            distance (int): Distance for route.
            priority (int): Priority for route.
            weight (int): Weight for route.
            comment (str): Comment for route
            blackhole (str): Enable or disable blackhole route.   ('enable', 'disable', or None=inherit)
            vrf (int): VRF number to set for route
            vdom (str): VDOM, if applicable, for route
        """

        # Initialize the parent class - we do set this here, because the subclass will first verify obj_id
        # is acceptable for this class type in the above attribute set functions
        super().__init__(api='cmdb', api_path='router', api_name='static', cli_path="config router static",
                         obj_id=routeid, vdom=vdom)

        ### Set parent class attributes ###
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'routeid': 'seq-num', 'dst': 'dst', 'device': 'device', 'gateway': 'gateway',
                           'distance': 'distance', 'priority': 'priority', 'weight': 'weight', 'comment': 'comments',
                           'blackhole': 'blackhole', 'vrf': 'vrf'}

        self._cli_ignore_attrs = ['routeid']

        # Set instance attributes
        self.routeid = routeid
        self.dst = dst
        self.device = device
        self.gateway = gateway
        self.distance = distance
        self.priority = priority
        self.weight = weight
        self.comment = comment
        self.blackhole = blackhole
        self.vrf = vrf

        # Update the parent defined obj_to_str attribute with this objects str representation
        self._obj_to_str += f", routeid={self.routeid}, dst={self.dst}, device={self.device}, gateway={self.gateway}," \
                          f"distance={self.distance}, priority={self.priority}, weight={self.weight}, " \
                          f"comment={self.comment}, blackhole={self.blackhole}, vrf={self.vrf}, vdom={self.vdom}"


    # Class Methods
    @classmethod
    def blackhole_route(cls, routeid: int = 0, dst: str = None, vdom: str = None, distance: int = None,
                        priority: int = None, weight: int = None, comment: str = None, vrf: int = None):
        """ Class Method to streamline config for blackhole  routes

        Args:
            routeid (int): ID of route, if not set defaults to 0
            dst (str): Destination network for route
            vdom (str): VDOM, if applicable for route
            distance (int): Set route distance
            priority (int): Set route priority
            weight (int): Set route weight
            comment (str): Set route comment
            vrf (int): Set route VRF

        Returns:
            Class Instance
        """

        device = None
        gateway = None
        blackhole = True

        obj = cls(routeid, dst, device, gateway, distance, priority, weight, comment, blackhole, vrf, vdom)
        return obj

    # Instance Methods
    def set_routeid(self, routeid):
        """ Set self.routeid to routeid if routeid is provided and valid, else set self.routeid to 0

        Args:
            routeid (int): Id for route.  If routeid = None, self.routeid set to 0

        Returns:
            None
        """
        if routeid is None:
            self.routeid = 0

        else:
            if isinstance(routeid, int):
                if 0 <= routeid <= 4294967295:
                    self.routeid = routeid
                else:
                    raise ValueError("'routeid' must be type int between 0 and 4294967295")
            else:
                raise ValueError("'routeid', must type int")

    def set_dst(self, dst):
        """ Set self.dst to dst if dst is valid ipv4 network/mask.  If no mask is set, mask defaults to 32.

        Args:
            dst (str): A valid IPv4 network/mask

        Returns:
            None
        """
        if dst is None:
            self.dst = None

        else:
            if isinstance(dst, str):
                try:
                    self.dst = str(ipaddress.ip_network(dst))
                except ValueError:
                    raise ValueError("'dst' must be a valid ipv4 or ipv6 network and mask")
            else:
                raise ValueError("'dst' must be type: str")

    def set_device(self, device):
        """ Set self.device to device if device contains valid values

        Args:
            device (str): Route destination device

        Returns:
            None
        """
        if device is None:
            self.device = None

        else:
            if isinstance(device, str) and 1 <= len(device) <= 35:
                self.device = device
            else:
                raise ValueError("'device' must be type str between 1 and 35 chars", device)

    def set_gateway(self, gateway):
        """ Set self.gateway to gateway if gateway is valid ipv4 address

        Args:
            gateway (str): Next-hop gateway.  Must be valid ipv4 address.

        Returns:
            None
        """
        if gateway is None:
            self.gateway = None

        else:
            if isinstance(gateway, str):
                try:
                    self.gateway = str(ipaddress.ip_address(gateway))
                except ValueError:
                    raise ValueError("'gateway', when set, must be a valid ipv4 address address")
            else:
                raise ValueError("'gateway', when set must be type: str, with a valid ipv4 address")

    def set_distance(self, distance):
        """ Set self.distance to distance if distance valid

        Args:
            distance (int): Route distance

        Returns:
            None
        """
        if distance is None:
            self.distance = None

        else:
            if isinstance(distance, int) and 1 <= distance <= 255:
                self.distance = distance
            else:
                raise ValueError("'distance', when set, must be type int with value between 1 and 255")

    def set_weight(self, weight):
        """ Set self.weight to weight if weight valid

        Args:
            weight (int): Route weight

        Returns:

        """
        if weight is None:
            self.weight = None

        else:
            if isinstance(weight, int) and 1 <= weight <= 255:
                self.weight = weight
            else:
                raise ValueError("'weight', when set, must be type int with value between 1 and 255")

    def set_priority(self, priority):
        """ Set self.priority to priority if priority valid

        Args:
            priority (int): Route priority

        Returns:
            None
        """
        if priority is None:
            self.priority = None

        else:
            if isinstance(priority, int) and 0 <= priority <= 4294967295:
                self.priority = priority
            else:
                raise ValueError("'priority', when set, must be type int with value between 0 and 4294967295")

    def set_vrf(self, vrf):
        """ Set self.vrf to vrf if vrf is valid

        Args:
            vrf (int): Route VRF

        Returns:
            None
        """
        if vrf is None:
            self.vrf = None

        else:
            if isinstance(vrf, int) and 0 <= vrf <= 31:
                self.vrf = vrf
            else:
                raise ValueError("'vrf', when set, must be type int with value between 0 and 31")

    def set_comment(self, comment):
        """ Set self.comment to comment if comment valid

        Args:
            comment: Route comment

        Returns:
            None
        """
        if comment is None:
            self.comment = None

        else:
            if isinstance(comment, str) and 1 <= len(comment) <= 255:
                self.comment = comment
            else:
                raise Exception("'comment', when set, must be type str between 1 and 255 chars")

    def set_blackhole(self, blackhole):
        """ Set self.blackhole to True, False if blackhole = True or False, else set to None

        Args:
            blackhole: Set blackhole True=enable, False=disable, None=inherit

        Returns:
            None
        """
        if blackhole is None:
            self.blackhole = None

        else:
            if isinstance(blackhole, bool):
                if blackhole == 'enable':
                    self.blackhole = 'enable'
                elif blackhole == 'disable':
                    self.blackhole = 'diable'
                else:
                    raise ValueError("'blackhole', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'blackhole', when set, must be type str()")
