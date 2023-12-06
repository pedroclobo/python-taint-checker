from typing import Set
from domain.Label import Label
from domain.MultiLabel import MultiLabel
from domain.MultiLabelling import MultiLabelling
from domain.Pattern import Pattern
from domain.Policy import Policy
from domain.Variable import Variable


class Vulnerabilities:
    """
    Collects all the illegal information flows discovered during the execution
    of the slice.
    """

    def __init__(
        self, policy: Policy, multilabelling: MultiLabelling = MultiLabelling()
    ):
        self.policy = policy
        self.multilabelling = multilabelling

    def get_policy(self) -> Policy:
        return self.policy

    def get_patterns(self) -> Set[Pattern]:
        return self.policy.get_patterns().copy()

    def get_multi_labelling(self) -> MultiLabelling:
        return self.multilabelling

    def add_label(self, pattern: Pattern, variable: Variable, label: Label = Label()):
        self.multilabelling.add_multilabel(MultiLabel({pattern: label}), variable)

    def add_label_with_source(
        self, pattern: Pattern, variable: Variable, source: Variable
    ):
        label = Label(sources=set(source))
        self.multilabelling.add_multilabel(MultiLabel({pattern: label}), variable)

    # is_source?

    # TODO

    def __repr__(self):
        return f"Vulnerabilities({self.policy}, {self.multilabelling})"
