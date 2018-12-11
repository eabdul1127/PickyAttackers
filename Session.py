class Session(object):
    def __init__(self, commands):
        self.commands = commands
        self.cmds = []
        for command in commands:
            self.cmds.append(command['Command'])
    def __repr__(self):
        return f'Session({self.cmds})'
    def __eq__(self, other):
        if isinstance(other, Session):
            for c1, c2 in zip(self.cmds, other.cmds):
                if c1 != c2:
                    return False
            return True
        else:
            return False
    def __ne__(self, other):
        return (not self.__eq__(other))
    def __hash__(self):
        return hash(self.__repr__())