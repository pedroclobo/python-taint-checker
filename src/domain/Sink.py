class Sink:
    def __init__(self, name):
        self.name = name

    def get_name(self) -> str:
        return self.name

    def __repr__(self):
        return self.name
