from fgobjlib import FgObject
import textwrap
import ipaddress


class FgRouteIPv4(FgObject):
    """FgRouteIPv4 class represents FortiGate Firewall static route object and provides methods for validating
    parameters and generating both cli and api configuration data for use in external configuration applications"""

    def __init__(self, route_id: int = None, dst: str = None, device: str = None, gateway: str = None,
                 distance: int = None, priority: int = None, weight: int = None, comment: str = None,
                 blackhole: bool = None, vrf: int = None, vdom: str = None):

        # Set Instance Constants
        self.API = 'cmdb'
        self.PATH = 'router'
        self.NAME = 'static'
        self.MKEY = None

        # Set Instance Variables
        super().__init__(vdom=vdom)
        self.set_route_id(route_id)
        self.set_dst(dst)
        self.set_device(device)
        self.set_gateway(gateway)
        self.set_vdom(vdom)
        self.set_distance(distance)
        self.set_priority(priority)
        self.set_weight(weight)
        self.set_comment(comment)
        self.set_blackhole(blackhole)
        self.set_vrf(vrf)


    @classmethod
    def standard_route(cls, route_id: int = 0, dst: str = None, device: str = None, gateway: str = None, vdom: str = None,
                 distance: int = 10, priority: int = 0, weight: int = 0, comment: str = None, vrf: int = 0):

        blackhole = False

        obj = cls(route_id, dst, device, gateway, distance, priority, weight, comment, blackhole, vrf, vdom)
        return obj

    @classmethod
    def blackhole_route(cls, route_id: int = 0, dst: str = None, vdom: str = None, distance: int = 10, priority: int = 0,
                  weight: int = 0, comment: str = None, vrf: int = 0):

        device = None
        gateway = None
        blackhole = True

        obj = cls(route_id, dst, device, gateway, distance, priority, weight, comment, blackhole, vrf, vdom)
        return obj

    def set_route_id(self, route_id):
        if route_id:
            if isinstance(route_id, int):
                if 0 <= route_id <= 4294967295:
                    self.route_id = route_id
                else:
                    raise ValueError("\"route_id\: must be type int between 0 and 4294967295")
            else:
                raise ValueError("\"route_id\" must type int")
        else:
            self.route_id = 0

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


    def get_cli_config_add(self):
        conf = ''
        if self.vdom: conf += "config vdom\nedit {}\n".format(self.vdom)

        if self.blackhole:
            conf += textwrap.dedent("""
                    config router static
                      edit {id}
                        set dst {dst}
                        set blackhole enable
                        set distance {distance}
                        set priority {priority}
                        set weight {weight}
                        set comment {comment}
                        set vrf {vrf}
                      end
                    end
                    """.format(id=self.route_id, dst=self.dst, distance=self.distance, priority=self.priority,
                               weight=self.weight, comment=self.comment, vrf=self.vrf))
        else:
            conf += textwrap.dedent("""
                    config router static
                      edit {id}
                        set dst {dst}
                        set gateway {gateway}
                        set device {device}
                        set distance {distance}
                        set priority {priority}
                        set weight {weight}
                        set comment {comment}
                        set vrf {vrf}
                      end
                    end
                    """.format(id=self.route_id, dst=self.dst, gateway=self.gateway, device=self.device,
                               distance=self.distance, priority=self.priority, weight=self.weight,
                               comment=self.comment, vrf=self.vrf))


        if self.vdom: conf += "end\n"

        return conf

    def get_cli_config_update(self):
        conf = self.get_cli_config_add()
        return conf

    def get_api_config_add(self):
        conf = {'api': self.API, 'path': self.PATH, 'name': self.NAME, 'mkey': self.MKEY, 'action': None}
        data = {}
        params = {}

        # Check if vdom is specific and add to params
        if self.vdom: params.update({'vdom': self.vdom})

        # Set the route info in data dictionary
        if self.route_id: data.update({'seq-num': self.route_id})
        if self.dst: data.update({'dst': str(self.dst)})
        if self.gateway: data.update({'gateway': str(self.gateway)})
        if self.device: data.update({'device': self.device})
        if self.blackhole: data.update({'blackhole': 'enable'})
        if self.distance: data.update({'distance': self.distance})
        if self.priority: data.update({'priority': self.priority})
        if self.weight: data.update({'weight': self.weight})
        if self.vrf: data.update({'vrf': self.vrf})

        # Add data and parameter dictionaries to conf dictionary
        conf.update({'data': data})
        conf.update({'parameters': params})

        return conf

    def get_api_config_update(self):
        if self.route_id: self.MKEY = self.route_id
        conf = self.get_api_config_add()

        return conf

    def get_cli_config_del(self):
        conf = {'api': self.API, 'path': self.PATH, 'name': self.NAME, 'mkey': self.MKEY, 'action': None}
        data = {}
        params = {}

        # Set the VDOM, if necessary
        if self.vdom: params.update({'vdom': self.vdom})

        if self.route_id:
            # Set the mkey value to interface name and updated other vars
            conf['mkey'] = self.route_id
            conf.update({'data': data})
            conf.update({'parameters': params})

        else:
            raise Exception("\"route_id\" must be set in order get or delete an existing route")

        return conf

    def get_api_config_del(self):
        if self.route_id > 0:
            mkey = self.route_id

            if self.vdom:
                params = {'vdom': self.vdom}
            else:
                params = {}

        else:
            raise Exception("Route id not specified, or is '0'. To delete, id must be a number greater than 0.")

        conf = {'api': self.API, 'path': self.PATH, 'name': self.NAME, 'mkey': mkey, 'action': None,
                'parameters': params,
                'data': None}

        return conf

    def get_api_config_get(self):
        if self.route_id > 0:
            mkey = self.route_id

            if self.vdom:
                params = {'vdom': self.vdom}
            else:
                params = {}

        else:
            raise Exception("Route id not specified, or is '0'. To get route info, id must be a number greater than 0.")

        conf = {'api': self.API, 'path': self.PATH, 'name': self.NAME, 'mkey': mkey, 'action': None,
                'parameters': params,
                'data': None}

        return conf
