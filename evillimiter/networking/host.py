from evillimiter.console.io import IO


class Host(object):
    def __init__(self, ip, mac, name):
        self.ip = ip
        self.mac = mac
        self.name = name
        self.spoofed = False
        self.limited = False
        self.blocked = False
        self.watched = False

    def __eq__(self, other):
        if not isinstance(other, Host):
            return NotImplemented
        return self.mac == other.mac and self.ip == other.ip

    def __hash__(self):
        return hash((self.ip, self.mac))

    def pretty_status(self):
        if self.limited:
            return "{}Limited{}".format(IO.Fore.LIGHTRED_EX, IO.Style.RESET_ALL)
        elif self.blocked:
            return "{}Blocked{}".format(IO.Fore.RED, IO.Style.RESET_ALL)
        else:
            return "Free"
