from typing import Dict
from domain.MultiLabel import MultiLabel
from domain.Variable import Variable


class MultiLabelling:
    def __init__(self, mapping: Dict[Variable, MultiLabel]):
        self.mapping = mapping

    def get_multilabel(self, name: Variable) -> MultiLabel:
        return self.mapping[name]

    def add_multilabel(self, multilabel: MultiLabel, name: Variable):
        self.mapping[name] = multilabel
