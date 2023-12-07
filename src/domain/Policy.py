import json

from typing import Dict, Set

from domain.MultiLabel import MultiLabel
from domain.Pattern import Pattern
from domain.Vulnerability import Vulnerability
from domain.Source import Source
from domain.Sanitizer import Sanitizer
from domain.Sink import Sink


class Policy:
    def __init__(self, patterns: Set[Pattern]) -> None:
        self.patterns = patterns

    def get_patterns(self) -> Set[Pattern]:
        return self.patterns

    def get_vulnerabilities(self) -> Set[Vulnerability]:
        return {pattern.get_vulnerability() for pattern in self.patterns}

    def get_illegal_flows(self, sink: Sink, multilabel: MultiLabel) -> MultiLabel:
        new_mapping = {}

        for pattern in multilabel.get_patterns():
            if pattern.has_sink(sink):
                new_mapping[pattern] = multilabel.get_label(pattern)

        return MultiLabel(new_mapping)

    def to_json(self) -> Dict:
        return {"patterns": [pattern.to_json() for pattern in self.patterns]}

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
