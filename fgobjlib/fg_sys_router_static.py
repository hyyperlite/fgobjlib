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
        blackhole (bool): Enable/Disable blackhole route
        vrf (int): vrf ID for route
        vdom (str): vdom for this route
    """

    def __init__(self, routeid: int = None, dst: str = None, device: str = None, gateway: str = None,
                 distance: int = None, priority: int = None, weight: int = None, comment: str = None,
                 blackhole: bool = None, vrf: int = None, vdom: str = None):
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
            blackhole (bool): Enable or disable blackhole route.  True=enable, False=disable, None=inherrit
            vrf (int): VRF number to set for route
            vdom (str): VDOM, if applicable, for route
        """

        # Initialize the parent class - we do set this here, because the subclass will first verify obj_id
        # is acceptable for this class type in the above attribute set functions
        super().__init__(api='cmdb', api_path='router', api_name='static', cli_path="config router static",
                         obj_id=routeid, vdom=vdom)

        ### Set parent class attributes ###
        # Map instance attribute names to fg attribute names
        self.data_attrs = {'routeid': 'seq-num', 'dst': 'dst', 'device': 'device', 'gateway': 'gateway',
                           'distance': 'distance', 'priority': 'priority', 'weight': 'weight', 'comment': 'comments',
                           'blackhole': 'blackhole', 'vrf': 'vrf'}

        self.cli_ignore_attrs = ['routeid']

        # Set instance attributes
        self.set_routeid(routeid)
        self.set_dst(dst)
        self.set_device(device)
        self.set_gateway(gateway)
        self.set_distance(distance)
        self.set_priority(priority)
        self.set_weight(weight)
        self.set_comment(comment)
        self.set_blackhole(blackhole)
        self.set_vrf(vrf)


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

    def set_routeid(self, routeid):
        """ Set self.routeid to routeid if routeid is provided and valid, else set self.routeid to 0

        Args:
            routeid (int): Id for route.  If routid = None, self.routeid set to 0

        Returns:
            None
        """
        if routeid:
            if isinstance(routeid, int):
                if 0 <= routeid <= 4294967295:
                    self.routeid = routeid
                else:
                    raise ValueError("\"routeid\: must be type int between 0 and 4294967295")
            else:
                raise ValueError("\"routeid\" must type int")
        else:
            self.routeid = 0

    def set_dst(self, dst):
        """ Set self.dst to dst if dst is valid ipv4 network/mask.  If no mask is set, mask defaults to 32.

        Args:
            dst (str): A valid IPv4 network/mask

        Returns:
            None
        """
        if dst:
            if isinstance(dst, str):
                try:
                    self.dst = str(ipaddress.ip_network(dst))
                except ValueError:
                    raise ValueError("\"dst\" must be a valid ipv4 or ipv6 network and mask")
            else:
                raise ValueError("\"dst\" must be type: str")
        else:
            self.dst = None

    def set_device(self, device):
        """ Set self.device to device if device contains valid values

        Args:
            device (str): Route destination device

        Returns:
            None
        """
        if device:
            if isinstance(device, str) and 1 <= len(device) <= 35:
                self.device = device
            else:
                raise ValueError("\"device\" must be type str between 1 and 35 chars", device)
        else:
            self.device = None

    def set_gateway(self, gateway):
        """ Set self.gateway to gateway if gateway is valid ipv4 address

        Args:
            gateway (str): Next-hop gateway.  Must be valid ipv4 address.

        Returns:
            None
        """
        if gateway:
            if isinstance(gateway, str):
                try:
                    self.gateway = str(ipaddress.ip_address(gateway))
                except ValueError:
                    raise ValueError("\"gateway\" must be a valid ipv4 or ipv6 address")
            else:
                raise ValueError("\"gateway\" must be type: str, with a valid ipv4 or ipv6 address")
        else:
            self.gateway = None

    def set_distance(self, distance):
        """ Set self.distance to distance if distance valid

        Args:
            distance (int): Route distance

        Returns:
            None
        """
        if distance:
            if isinstance(distance, int) and  1 <= distance <= 255:
                self.distance = distance
            else:
                raise ValueError("\"distance\" must be type int with value between 1 and 255")
        else:
            self.distance = None

    def set_weight(self, weight):
        """ Set self.weight to weight if weight valid

        Args:
            weight (int): Route weight

        Returns:

        """
        if weight:
            if isinstance(weight, int) and  1 <= weight <= 255:
                self.weight = weight
            else:
                raise ValueError("\"weight\" must be type int with value between 1 and 255")
        else:
            self.weight = None

    def set_priority(self, priority):
        """ Set self.priority to priority if priority valid

        Args:
            priority (int): Route priority

        Returns:
            None
        """
        if priority:
            if isinstance(priority, int) and  0 <= priority <= 4294967295:
                self.priority = priority
            else:
                raise ValueError("\"priority\" must be type int with value between 0 and 4294967295")
        else:
            self.priority = None

    def set_vrf(self, vrf):
        """ Set self.vrf to vrf if vrf is valid

        Args:
            vrf (int): Route VRF

        Returns:
            None
        """
        if vrf:
            if isinstance(vrf, int) and  0 <= vrf <= 31:
                self.vrf = vrf
            else:
                raise ValueError("\"vrf\" must be type int with value between 0 and 31")
        else:
            self.vrf = None

    def set_comment(self, comment):
        """ Set self.comment to comment if comment valid

        Args:
            comment: Route comment

        Returns:
            None
        """
        if comment:
            if isinstance(comment, str) and 1 <= len(comment) <= 255:
                self.comment = comment
            else:
                raise Exception("\"comment\", when set, must be type str between 1 and 255 chars")
        else:
            self.comment = None

    def set_blackhole(self, blackhole):
        """ Set self.blackhole to True, False if blackhole = True or False, else set to None

        Args:
            blackhole: Set blackhold True=enable, False=disable, None=inherit

        Returns:
            None
        """
        if isinstance(blackhole, bool):
            self.blackhole = 'enable' if blackhole else 'disable'
        else:
            self.blackhole = None