import json

from typing import Dict, Set

from domain.Label import Label
from domain.MultiLabel import MultiLabel
from domain.MultiLabelling import MultiLabelling
from domain.MultiSink import MultiSink
from domain.Pattern import Pattern
from domain.Policy import Policy
from domain.Sink import Sink
from domain.Source import Source
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

    def get_policy(self) -> Policy:
        return self.policy

    def get_multi_labelling(self) -> MultiLabelling:
        return self.multilabelling

    def get_patterns(self) -> Set[Pattern]:
        return self.policy.get_patterns()

    def add_empty_label(self, pattern: Pattern, variable: Variable) -> None:
        label = Label()
        self.multilabelling.add_multi_label(MultiLabel({pattern: label}), variable)

    def add_source_to_label(
        self, pattern: Pattern, variable: Variable, source: Source, lineno: int
    ) -> None:
        label = Label(sources={(source, lineno)})
        self.multilabelling.add_multi_label(MultiLabel({pattern: label}), variable)

    def add_sink(
        self, pattern: Pattern, sink: Sink, lineno: int, variable: Variable
    ) -> None:
        self.multi_sink.add_sink(pattern, sink, lineno, variable)

    def get_illegal_flows(self) -> Set[IllegalFlow]:
        illegal_flows = set()

        for pattern in self.multilabelling.get_patterns():
            i = 1
            for variable in self.multilabelling.get_variables_for_pattern(pattern):
                label = self.multilabelling.get_multi_label(variable).get_label(pattern)
                for source, source_lineno in label.get_sources():
                    for sink, sink_lineno in self.multi_sink.get_sinks(pattern):
                        if self.multi_sink.is_variable_in_sink(
                            pattern, sink, sink_lineno, variable
                        ):
                            illegal_flows.add(
                                IllegalFlow(
                                    pattern.get_vulnerability() + "_" + str(i),
                                    source,
                                    source_lineno,
                                    sink,
                                    sink_lineno,
                                )
                            )
                            i += 1

        return illegal_flows

    def to_json(self) -> Dict:
        return {
            "policy": self.policy.to_json(),
            "multilabelling": self.multilabelling.to_json(),
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
