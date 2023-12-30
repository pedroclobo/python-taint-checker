import json

from typing import Dict, List, Set

from domain.MultiLabel import MultiLabel
from domain.Sink import Sink
from domain.Variable import Variable
from domain.Pattern import Pattern


class MultiLabelling:
    """
    Maps variables to multilabels.
    """

    def __init__(self, mapping: Dict[Variable, MultiLabel] = {}) -> None:
        self.mapping = mapping

    def has_multi_label(self, name: Variable) -> bool:
        return name in self.mapping

    def get_multi_label(self, name: Variable) -> MultiLabel:
        if not self.has_multi_label(name):
            return MultiLabel()
        return self.mapping[name]

    def get_multi_labels(self) -> Set[MultiLabel]:
        return set(self.mapping.values())

    def add_multi_label(self, multilabel: MultiLabel, name: Variable) -> None:
        self.mapping[name] = multilabel

    def get_patterns(self) -> Set[Pattern]:
        return set.union(
            *[multi_label.get_patterns() for multi_label in self.get_multi_labels()]
        )

    def get_variables_for_pattern(self, pattern: Pattern) -> Set[Variable]:
        return {
            variable
            for variable, multilabel in self.mapping.items()
            if pattern in multilabel.get_patterns()
        }

    def to_json(self) -> Dict:
        return {
            "mapping": [
                (name, multilabel.to_json())
                for name, multilabel in self.mapping.items()
            ]
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
