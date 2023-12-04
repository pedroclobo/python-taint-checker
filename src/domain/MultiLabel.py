from typing import Dict, Set

from domain.Label import Label
from domain.Pattern import Pattern


class MultiLabel:
    """
    Generalizes the Label class in order to be able to represent distinct labels
    corresponding to different patterns.
    """

    def __init__(self, mapping: Dict[Pattern, Label]):
        self.mapping = mapping

    def get_mapping(self) -> Dict[Pattern, Label]:
        return self.mapping

    def get_patterns(self) -> Set[Pattern]:
        return self.mapping.keys()

    def get_label(self, pattern: Pattern) -> Label:
        if pattern not in self.mapping:
            return Label()
        return self.mapping[pattern]

    def add_label(self, label: Label, pattern: Pattern):
        self.mapping[pattern] = label

    def combine(self, other: "MultiLabel"):
        new_mapping = {}
        patterns = self.get_patterns().union(other.get_patterns())

        for pattern in patterns:
            new_mapping[pattern] = self.get_label(pattern).combine(
                other.get_label(pattern)
            )

        return MultiLabel(new_mapping)
