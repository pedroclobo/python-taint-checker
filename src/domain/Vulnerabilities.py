import json

from typing import Dict, Set

from domain.MultiLabel import MultiLabel
from domain.MultiLabelling import MultiLabelling
from domain.MultiSink import MultiSink
from domain.Pattern import Pattern
from domain.Policy import Policy
from domain.Sink import Sink
from domain.Variable import Variable
from domain.IllegalFlow import IllegalFlow


class Vulnerabilities:
    """
    Collects all the illegal information flows discovered during the execution
    of the slice.
    """

    def __init__(
        self, policy: Policy, multilabelling: MultiLabelling = MultiLabelling()
    ) -> None:
        self.policy = policy
        self.multilabelling = multilabelling
        self.multi_sink = MultiSink()
        self.illegal_flows: Set[IllegalFlow] = set()

    def get_patterns(self) -> Set[Pattern]:
        return self.policy.get_patterns()

    def has_multi_label(self, variable: Variable) -> bool:
        return self.multilabelling.has_multi_label(variable)

    def get_multi_label(self, variable: Variable) -> MultiLabel:
        return self.multilabelling.get_multi_label(variable)

    def add_multi_label(self, label: MultiLabel, variable: Variable) -> None:
        self.multilabelling.add_multi_label(label, variable)

    def add_illegal_flow(self, illegal_flow: IllegalFlow) -> None:
        self.illegal_flows.add(illegal_flow)

    def add_sink(
        self,
        pattern: Pattern,
        sink: Sink,
        lineno: int,
    ) -> None:
        self.multi_sink.add_sink(pattern, sink, lineno)

    def get_illegal_flows(self) -> Set[IllegalFlow]:
        return self.illegal_flows

    def to_json(self) -> Dict:
        return {
            "policy": self.policy.to_json(),
            "multilabelling": self.multilabelling.to_json(),
            "multi_sink": self.multi_sink.to_json(),
            "illegal_flows": [
                illegal_flow.to_json() for illegal_flow in self.illegal_flows
            ],
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
