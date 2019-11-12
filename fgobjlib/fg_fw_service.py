from fgobjlib import FgObject
import re

class FgFwService(FgObject):
    """
    FgFwService class represents FortiGate Firewall service custom object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications

    Currently only supports tcp/udp/sctp and icmp type objects

    Currently, does not support proxy objects or setting of iprange, fqdn, tcp timers (halfopen/halfclose/timewait),
    or check-reset-range
    """

    def __init__(self, name: str = None, vdom: str = None, protocol: str = None, tcp_portrange: list = None,
                 udp_portrange: list = None, sctp_portrange: list = None, comment: str = None, visibility: bool = None,
                 session_ttl: int = None, udp_idle_timer: int = None, category: str = None, icmp_type: int = None):

        # Initialize the parent class
        super().__init__(api='cmdb', api_path='firewall.service', api_name='custom', api_mkey=None, obj_id=name,
                         vdom=vdom)

        ### Set parent class attributes ###
        # CLI config path for this object type
        self.cli_path = "config firewall service custom"

        # Map instance attribute names to fg attribute names
        self.data_attrs = {'name': 'name',  'protocol': 'protocol', 'tcp_portrange': 'tcp-portrange',
                           'udp_portrange': 'udp-portrange', 'sctp_portrange': 'sctp-portrange', 'icmp_type': 'icmp-type',
                           'comment': 'comments', 'visibility': 'visibility', 'session_ttl': 'session-ttl',
                           'udp_idle_timer': 'udp-idle-timer', 'category': 'category'}

        self.cli_ignore_attrs = []

        # Set instance attributes
        self.set_name(name)
        self.set_protocol(protocol)
        self.set_portrange(tcp_portrange, 'tcp_portrange')
        self.set_portrange(udp_portrange, 'udp_portrange')
        self.set_portrange(sctp_portrange, 'sctp_portrange')
        self.set_comment(comment)
        self.set_visibility(visibility)
        self.set_session_ttl(session_ttl)
        self.set_udp_idle_timer(udp_idle_timer)
        self.set_category(category)
        self.set_icmp_type(icmp_type)


    def set_name(self, name):
        if name:
            if name.isspace(): raise Exception("\"intf\", cannot be an empty string")
            if isinstance(name, str):
                if 1 <= len(name) <= 79:
                    self.name = name
                else:
                    raise Exception("\"name\", must be less than or equal to 79 chars")
            else:
                raise Exception("\"name\", must be a string")
        else:
            raise Exception("Value \"name\" is required but was not provided")

    def set_protocol(self, protocol):
        if protocol:
            if protocol.lower() in ['tcp', 'udp', 'sctp', 'tcp/udp/sctp']:
                self.protocol = 'TCP/UDP/SCTP'
            elif protocol.lower() == 'icmp':
                self.protocol = 'ICMP'
            elif protocol.lower() == 'ip':
                self.protocol = 'IP'
            else:
                raise ValueError("\"protocol\" specified is unsupported")
        else:
            self.protocol = 'TCP/UDP/SCTP'

    def set_portrange(self, range, protocol):
        if range and protocol:

            # If range is provided as a single range in str format
            if isinstance(range, str):
                # check that string is only numbers or number dash number
                if re.match(r'(^[\d]+$)|(^[\d]+-[\d]+$)', range):
                    setattr(self, protocol, range)
                else:
                    raise ValueError("\"{}\" portrange specified {} is not a valid range.  Must be str of <digits> or "
                                     "<digits>-<digits>".format(protocol, range))

            # If a list of port ranges is provided in 'range' var
            elif isinstance(range, list):
                range_list = ''
                for item in range:
                    if isinstance(item, str):
                        # check that string is only numbers or number dash number
                        if re.match('(^[\d]+$)|(^[\d]+-[\d]+$)', item):
                            range_list += ' {}'.format(item)
                        else:
                            raise ValueError(
                                "\"{}\" portrange specified: {} is not a valid range.  Must be str of <digits> or "
                                "<digits>-<digits>".format(protocol, item))
                setattr(self, protocol, range_list.lstrip())
        else:
            setattr(self, protocol, None)


    def set_visibility(self, visibility):
        if visibility:
            if isinstance(visibility, bool):
                self.visibility = 'enable' if visibility else 'disable'
            else:
                raise ValueError("\"visibility\", when set, must be type bool")
        else:
            self.visibility = None

    def set_comment(self, comment):
        if comment:
            if isinstance(comment, str):
                if 1 <= len(comment) <= 255:
                    self.comment = comment
                else:
                    raise Exception("\"description\", when set, must be type str between 1 and 1,023 chars")
            else:
                raise Exception("\"description\", when set, must be type str")
        else:
            self.comment = None

    def set_session_ttl(self, session_ttl):
        if session_ttl:
            if isinstance(session_ttl, int):
                if 300 <= session_ttl <= 2764800:
                    self.session_ttl = session_ttl
                else:
                    raise ValueError("\"session_ttl\", when set, must be type int between 300 and 2764800")
            else:
                raise ValueError("\"session_ttl\", when set, must be type int")
        else:
            self.session_ttl = None

    def set_udp_idle_timer(self, timer):
        if timer:
            if isinstance(timer, int):
                if 0 <= timer <= 864000:
                    self.udp_idle_timer = timer
                else:
                    raise ValueError("\"udp_idle_timer\", when set, must be type int between 0 and 86400")
            else:
                raise ValueError("\"udp_idle_timer\", when set, must be type int")
        else:
            self.udp_idle_timer = None

    def set_category(self, category):
        if category:
            if isinstance(category, str):
                if 1 <= len(category) <= 63:
                    self.category = category
                else:
                    raise ValueError("\"category\", when set, must be type str between 1 and 63 chars")
            else:
                raise ValueError("\"category\", when set, must be type str")
        else:
            self.category = None

    def set_icmp_type(self, icmp_type):
        if icmp_type:
            if isinstance(icmp_type, int):
                if 0 <= icmp_type <= 255:
                    self.icmp_type = icmp_type
                else:
                    raise ValueError("\"icmp_type\", when set, must be type int between 0 and 255")
            else:
                raise ValueError("\"icmp_type\", when set, must be type int")
        else:
            self.icmp_type = None