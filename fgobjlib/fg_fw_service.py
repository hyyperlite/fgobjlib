from fgobjlib import FgObject
import re

class FgFwService(FgObject):
    """
    FgFwService class represents FortiGate Firewall service custom object and provides methods for validating parameters
    and generating both cli and api configuration data for use in external configuration applications

    Currently only supports tcp/udp/sctp and icmp type objects

    Currently, does not support proxy objects or setting of iprange, fqdn, tcp timers (halfopen/halfclose/timewait),
    or check-reset-range

    Attributes:
            name (str): Name of this FG object
            vdom: (str): Vdom associated with this FG object
            protocol (str): Protocol type for this FG service object
            tcp_portrange (list): TCP port range. May be string or list of strings.  ex. ['80', '1024-65553']
            udp_portrange (list): UDP port range.  May be string or list of strings.  ex. ['80', '1024-65553']
            sctp_portrange (list): SCTP port range.  May be string or list of strings. ex. ['80', '1024-65553']
            protocol_number (int):  IP protocol Number
            comment (str): Comment for this object
            visibility (str): Visibility of this object in GUI.  ('enable', 'disable', or None=inherit)
            session_ttl (int):  Session TTL for TCP sessions
            udp_idle_timer (int): Idle timer setting for UDP sessions
            category (str): Category to assign service object to in FG
            icmptype (int): Value of icmp type.  Used when self's protocol is 'icmp'
            icmpcode (int): Value of icmp type.  Used when self's protocol is 'icmp'
    """

    def __init__(self, name: str = None, vdom: str = None, protocol: str = None, tcp_portrange: list = None,
                 udp_portrange: list = None, sctp_portrange: list = None, protocol_number: int = None,
                 comment: str = None, visibility: str = None, session_ttl: int = None, udp_idle_timer: int = None,
                 category: str = None, icmptype: int = None, icmpcode: int = None):
        """
        Args:
            name (str): Name of this FG object
            vdom: (str): Vdom associated with this FG object
            protocol (str): Protocol type for this FG service object
            tcp_portrange (list): TCP port range. May be string or list of strings.  ex. ['80', '1024-65553']
            udp_portrange (list): UDP port range.  May be string or list of strings.  ex. ['80', '1024-65553']
            sctp_portrange (list): SCTP port range.  May be string or list of strings. ex. ['80', '1024-65553']
            protocol_number (int): IP Protocol Number. Use when self's protocol set to 'ip'.
            comment (str): Comment for this object
            visibility (str): Visibility of this object in GUI.  ('enable', 'disable', or None=inherit)
            session_ttl (int):  Session TTL for TCP sessions
            udp_idle_timer (int): Idle timer setting for UDP sessions
            category (str): Category to assign service object to in FG
            icmptype (int): Value of icmp type.  Used when self's protocol is 'icmp'
            icmpcode (int): Value of icmp code.  Used when self's protocol is 'icmp'
        """

        # Initialize the parent class
        super().__init__(api='cmdb', api_path='firewall.service', api_name='custom',
                         cli_path="config firewall service custom", obj_id=name, vdom=vdom)

        ##### Set parent class attributes #####
        # Map instance attribute names to fg attribute names
        self._data_attrs = {'name': 'name',  'protocol': 'protocol', 'tcp_portrange': 'tcp-portrange',
                           'udp_portrange': 'udp-portrange', 'sctp_portrange': 'sctp-portrange',
                           'icmptype': 'icmptype', 'comment': 'comments', 'visibility': 'visibility',
                           'session_ttl': 'session-ttl', 'udp_idle_timer': 'udp-idle-timer', 'category': 'category',
                           'protocol_number': 'protocol-number', 'icmpcode': 'icmpcode'}

        # Set attributes to ignore on CLI based configuration
        self._cli_ignore_attrs = []

        # Set instance attributes
        self.set_name(name)
        self.set_protocol(protocol)
        self.set_tcp_portrange(tcp_portrange)
        self.set_udp_portrange(udp_portrange)
        self.set_sctp_portrange(sctp_portrange)
        self.set_protocol_number(protocol_number)
        self.set_comment(comment)
        self.set_visibility(visibility)
        self.set_session_ttl(session_ttl)
        self.set_udp_idle_timer(udp_idle_timer)
        self.set_category(category)
        self.set_icmptype(icmptype)
        self.set_icmpcode(icmpcode)

        # Update the parent defined obj_to_str attribute with this objects str representation
        self._obj_to_str += f', name={self.name}, protocol={self.protocol}, tcp_portrange={self.tcp_portrange}'



    # Static Methods
    @staticmethod
    def _validate_and_get_portrange(range):
        """ Return port range or list (as a string) of port ranges if port range is formatted as expected

        Args:
            range (list): Port range. May be string or list of strings.  ex. '80'  or '100-300' or ['80', '100-300']

        Returns:
            String
        """
        if range is None:
            return None
        else:
            # If range is provided as a single range in str format
            if isinstance(range, str):
                # check that string is only numbers or number dash number
                if re.match(r'(^[\d]+$)|(^[\d]+-[\d]+$)', range):
                    return range
                else:
                    raise ValueError(f"portrange specified {range} is not a valid.  Must be str of <digits> or "
                                     "<digits>-<digits>")

            # If a list of port ranges is provided in 'range' var
            elif isinstance(range, list):
                range_list = ''
                for item in range:
                    if isinstance(item, str):
                        # check that string is only numbers or number dash number
                        if re.match('(^[\d]+$)|(^[\d]+-[\d]+$)', item):
                            range_list += f' {item}'
                        else:
                            raise ValueError(
                                f"portrange specified: {item} is not a valid range.  Must be str of <digits> or "
                                "<digits>-<digits>")

                # Set self.<obj_type> with range_list values
                return range_list.lstrip()

    # Instance Methods
    def set_name(self, name):
        """ Set self.name to name if name meets requirements

        Args:
            name (str): Name to set to self object

        Returns:
            None
        """
        if name is None:
            self.name = None
            if name.isspace(): raise Exception("'name', cannot be an empty string")

        else:
            if isinstance(name, str):
                if 1 <= len(name) <= 79:
                    self.name = name
                else:
                    raise Exception("'name', must be less than or equal to 79 chars")
            else:
                raise Exception("'name', must be a string")

    def set_protocol(self, protocol):
        """ Set self.protocol to 'protocol' if valid 'protocol' provided

        Args:
            protocol (str): Type of protocol this object represents.  Options: 'tcp/udp/sctp', 'icmp', 'ip'

        Returns:
            None
        """
        if protocol is None:
            self.protocol = None

        else:
            if protocol.lower() in ['tcp', 'udp', 'sctp', 'tcp/udp/sctp']:
                self.protocol = 'TCP/UDP/SCTP'
            elif protocol.lower() == 'icmp':
                self.protocol = 'ICMP'
            elif protocol.lower() == 'ip':
                self.protocol = 'IP'
            else:
                raise ValueError("'protocol' specified is unsupported")



    def set_tcp_portrange(self, range):
        """ Set self.tcp_portrange to range returned from static method _validate_and_get_portrange()

        Args:
            range (list):  A Port range. May be string or list of strings.  ex. '80'  or '100-300' or ['80', '100-300']

        Returns:
            None
        """
        self.tcp_portrange = self._validate_and_get_portrange(range)

    def set_udp_portrange(self, range):
        """ Set self.udp_portrange to range returned from static method _validate_and_get_portrange()

        Args:
            range (list):  A Port range. May be string or list of strings.  ex. '80'  or '100-300' or ['80', '100-300']

        Returns:
            None
        """
        self.udp_portrange = self._validate_and_get_portrange(range)

    def set_sctp_portrange(self, range):
        """ Set self.sctp_portrange to range returned from static method _validate_and_get_portrange()

        Args:
            range (list):  A Port range. May be string or list of strings.  ex. '80'  or '100-300' or ['80', '100-300']

        Returns:
            None
        """
        self.sctp_portrange = self._validate_and_get_portrange(range)


    def set_protocol_number(self, protocol_number):
        """ Set self.protocol_number to protocol_number if protocol_number provided is valid. If not provided set None

        (Used when self.type is set to 'IP')

        Args:
            protocol_number (int): protocol number in range 0-254

        Returns:
            None
        """
        if protocol_number is None:
            self.protocol_number = None

        else:
            if isinstance(protocol_number, int):
                if 0 <= protocol_number <= 254:
                    self.protocol_number = protocol_number
                else:
                    raise ValueError("'protocol_number', when set, must be type int between 1 and 254")
            else:
                raise ValueError("'protocol_number', when set, must be type int")

    def set_visibility(self, visibility):
        """ Set self.visibility

        Args:
            visibility (str): object visibility in GUI.  ('enable', 'disable', or None=inherit)

        Returns:
            None
        """
        if visibility is None:
            self.visibility = None

        else:
            if isinstance(visibility, str):
                if visibility == 'enable':
                    self.visibility = 'enable'
                elif visibility == 'disable':
                    self.visibility = 'disable'
                else:
                    raise ValueError("'visibility', when set, must be type str() with value 'enable' or 'disable'")
            else:
                raise ValueError("'visibility', when set, must be type str()")

    def set_comment(self, comment):
        """ Set self.comment to 'comment' if comment string within requirements

        Args:
            comment (str):  Comment for this policy object

        Returns:
            None
        """
        if comment is None:
            self.comment = None

        else:
            if isinstance(comment, str):
                if 1 <= len(comment) <= 255:
                    self.comment = comment
                else:
                    raise Exception("'description', when set, must be type str between 1 and 1,023 chars")
            else:
                raise Exception("'description', when set, must be type str")

    def set_session_ttl(self, session_ttl):
        """ Set self.session_ttl to session_ttl if session_ttl provided is valid

        Args:
            session_ttl (int): Session TTL for service object.  Acceptable range = 1-2764800

        Returns:
            None
        """
        if session_ttl is None:
            self.session_ttl = None

        else:
            if isinstance(session_ttl, int):
                if 300 <= session_ttl <= 2764800:
                    self.session_ttl = session_ttl
                else:
                    raise ValueError("'session_ttl', when set, must be type int between 300 and 2764800")
            else:
                raise ValueError("'session_ttl', when set, must be type int")

    def set_udp_idle_timer(self, timer):
        """ set self.udp_idle_timer to timer if timer valid

        Args:
            timer (int): Udp idle timer for this service object.  Acceptable range = 0-86400

        Returns:
            None
        """
        if timer is None:
            self.udp_idle_timer = None

        else:
            if isinstance(timer, int):
                if 0 <= timer <= 864000:
                    self.udp_idle_timer = timer
                else:
                    raise ValueError("'udp_idle_timer', when set, must be type int between 0 and 86400")
            else:
                raise ValueError("'udp_idle_timer', when set, must be type int")

    def set_category(self, category):
        """ Set self.category if category provided is valid

        Args:
            category (str): Set FortiGate category for this service object.  String between 1 and 63 chars.

        Returns:
            None
        """
        if category is None:
            self.category = None

        else:
            if isinstance(category, str):
                if 1 <= len(category) <= 63:
                    self.category = category
                else:
                    raise ValueError("'category', when set, must be type str between 1 and 63 chars")
            else:
                raise ValueError("'category', when set, must be type str")

    def set_icmptype(self, icmptype):
        """ Set self.icmptype to icmp_type if icmptype valid

        Args:
            icmptype (int): ICMP type.   Integer between 0 and 255.

        Returns:
            None
        """
        if icmptype is None:
            self.icmptype = None

        else:
            if isinstance(icmptype, int):
                if 0 <= icmptype <= 255:
                    self.icmptype = icmptype
                else:
                    raise ValueError("'icmptype', when set, must be type int between 0 and 255")
            else:
                raise ValueError("'icmptype', when set, must be type int")

    def set_icmpcode(self, icmpcode):
        """ Set self.icmpcode to icmpcode if icmp_type valid

        Args:
            icmpcode (int): ICMP code.   Integer between 0 and 255.

        Returns:
            None
        """
        if icmpcode is None:
            self.icmpcode = None

        else:
            if isinstance(icmpcode, int):
                if 0 <= icmpcode <= 255:
                    self.icmpcode = icmpcode
                else:
                    raise ValueError("'icmpcode', when set, must be type int between 0 and 255")
            else:
                raise ValueError("'icmpcode', when set, must be type int")