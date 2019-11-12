from fgobjlib import FgObject
import ipaddress


class FgRouteIPv4(FgObject):
    """FgRouteIPv4 class represents FortiGate Firewall static route object and provides methods for validating
    parameters and generating both cli and api configuration data for use in external configuration applications"""

    def __init__(self, routeid: int = None, dst: str = None, device: str = None, gateway: str = None,
                 distance: int = None, priority: int = None, weight: int = None, comment: str = None,
                 blackhole: bool = None, vrf: int = None, vdom: str = None):

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

        # Initialize the parent class - we do set this here, because the subclass will first verify obj_id
        # is acceptable for this class type in the above attribute set functions
        super().__init__(vdom=vdom, api='cmdb', api_path='router', api_name='static', api_mkey=None,
                         obj_id=self.routeid)

        ### Set parent class attributes ###
        # CLI config path for this object type
        self.cli_path = "config router static"

        # Map instance attribute names to fg attribute names
        self.data_attrs = {'routeid': 'seq-num', 'dst': 'dst', 'device': 'device', 'gateway': 'gateway',
                           'distance': 'distance', 'priority': 'priority', 'weight': 'weight', 'comment': 'comments',
                           'blackhole': 'blackhole', 'vrf': 'vrf'}

        self.cli_ignore_attrs = ['routeid']

    @classmethod
    def standard_route(cls, routeid: int = 0, dst: str = None, device: str = None, gateway: str = None, vdom: str = None,
                 distance: int = 10, priority: int = 0, weight: int = 0, comment: str = None, vrf: int = 0):

        blackhole = False

        obj = cls(routeid, dst, device, gateway, distance, priority, weight, comment, blackhole, vrf, vdom)
        return obj

    @classmethod
    def blackhole_route(cls, routeid: int = 0, dst: str = None, vdom: str = None, distance: int = 10, priority: int = 0,
                  weight: int = 0, comment: str = None, vrf: int = 0):

        device = None
        gateway = None
        blackhole = True

        obj = cls(routeid, dst, device, gateway, distance, priority, weight, comment, blackhole, vrf, vdom)
        return obj

    def set_routeid(self, routeid):
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
        if dst:
            if isinstance(dst, str):
                try:
                    self.dst = ipaddress.ip_network(dst)
                except ValueError:
                    raise ValueError("\"dst\" must be a valid ipv4 or ipv6 network and mask")
            else:
                raise ValueError("\"dst\" must be type: str")
        else:
            self.dst = None

    def set_device(self, device):
        if device:
            if isinstance(device, str) and 1 <= len(device) <= 35:
                self.device = device
            else:
                raise ValueError("\"device\" must be type str between 1 and 35 chars", device)
        else:
            self.device = None

    def set_gateway(self, gateway):
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
        if distance:
            if isinstance(distance, int) and  1 <= distance <= 255:
                self.distance = distance
            else:
                raise ValueError("\"distance\" must be type int with value between 1 and 255")
        else:
            self.distance = None

    def set_weight(self, weight):
        if weight:
            if isinstance(weight, int) and  1 <= weight <= 255:
                self.weight = weight
            else:
                raise ValueError("\"weight\" must be type int with value between 1 and 255")
        else:
            self.weight = None

    def set_priority(self, priority):
        if priority:
            if isinstance(priority, int) and  0 <= priority <= 4294967295:
                self.priority = priority
            else:
                raise ValueError("\"priority\" must be type int with value between 0 and 4294967295")
        else:
            self.priority = None

    def set_vrf(self, vrf):
        if vrf:
            if isinstance(vrf, int) and  0 <= vrf <= 31:
                self.vrf = vrf
            else:
                raise ValueError("\"vrf\" must be type int with value between 0 and 31")
        else:
            self.vrf = None

    def set_comment(self, comment):
        if comment:
            if isinstance(comment, str) and 1 <= len(comment) <= 255:
                self.comment = comment
            else:
                raise Exception("\"comment\", when set, must be type str between 1 and 255 chars")
        else:
            self.comment = None

    def set_blackhole(self, blackhole):
        if isinstance(blackhole, bool):
            self.blackhole = 'enable' if blackhole else 'disable'
        else:
            self.blackhole = None