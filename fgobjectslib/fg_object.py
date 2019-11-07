class FgObject:
    def __init__(self, vdom: str = None):
        self.set_vdom(vdom)

    def set_vdom(self, vdom):
        if vdom:
            if isinstance(vdom, str):
                # vdom names cannot have spaces so check for spaces and throw error if there are
                for char in vdom:
                    if str.isspace(char):
                        raise Exception("\"vdom\", str not allowed to contain whitespace")

                # Check vdom name string length meets FG requriements
                if 1 <= len(vdom) <= 31:
                    self.vdom = vdom
                else:
                    raise Exception("\"vdom\", when set, must be an str between 1 and 31 chars")
            else:
                raise Exception("\"vdom\", when set, must be a str")
        else:
            self.vdom = None