from typing import Dict
from domain.MultiLabel import MultiLabel
from domain.Variable import Variable


class MultiLabelling:
    def __init__(self, mapping: Dict[Variable, MultiLabel] = {}):
        self.mapping = mapping

    def has_mutilabel(self, name: Variable) -> bool:
        return name in self.mapping

    def get_multilabel(self, name: Variable) -> MultiLabel:
        if not self.has_mutilabel(name):
            raise ValueError(f"Variable {name} does not have a multilabel")
        return self.mapping[name]

    def add_multilabel(self, multilabel: MultiLabel, name: Variable):
        if self.has_mutilabel(name):
            self.mapping[name] = multilabel.combine(self.get_multilabel(name))
        else:
            self.mapping[name] = multilabel

    def override_multilabel(self, multilabel: MultiLabel, name: Variable):
        self.mapping[name] = multilabel

    def __repr__(self):
        return f"MultiLabelling({self.mapping})"
