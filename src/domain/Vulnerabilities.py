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

    def get_patterns(self) -> Set[Pattern]:
        return self.policy.get_patterns()

    def get_multi_label(self, variable: Variable) -> MultiLabel:
        return self.multilabelling.get_multi_label(variable)

    def add_multi_label(self, label: MultiLabel, variable: Variable) -> None:
        self.multilabelling.add_multi_label(label, variable)

    def add_sink(
        self,
        pattern: Pattern,
        sink: Sink,
        lineno: int,
    ) -> None:
        self.multi_sink.add_sink(pattern, sink, lineno)

    def get_illegal_flows(self) -> Set[IllegalFlow]:
        illegal_flows = set()

        for pattern in self.multilabelling.get_patterns():
            i = 1
            for sink, sink_lineno in self.multi_sink.get_sinks(pattern):
                label = self.multilabelling.get_multi_label(sink).get_label(pattern)
                for source, source_lineno in label.get_sources():
                    if sink == source:
                        continue
                    sanitizers = list(label.get_sanitizers_for_source(source))
                    illegal_flows.add(
                        IllegalFlow(
                            pattern.get_vulnerability() + "_" + str(i),
                            source,
                            source_lineno,
                            sink,
                            sink_lineno,
                            True,
                            [] if len(sanitizers) == 0 else [sanitizers],
                        )
                    )
                    i += 1

        return illegal_flows

    def to_json(self) -> Dict:
        return {
            "policy": self.policy.to_json(),
            "multilabelling": self.multilabelling.to_json(),
            "multi_sink": self.multi_sink.to_json(),
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
