from typing import Set
from domain.MultiLabel import MultiLabel

from domain.Pattern import Pattern
from domain.Vulnerability import Vulnerability
from domain.Source import Source
from domain.Sanitizer import Sanitizer
from domain.Sink import Sink


class Policy:
    def __init__(self, patterns: Set[Pattern]):
        self.patterns = patterns

    def get_vulnerabilities(self) -> Set[Vulnerability]:
        return [pattern.get_vulnerability() for pattern in self.patterns]

    def get_vulnerabilities_with_source(self, source: Source) -> Set[Vulnerability]:
        return [
            pattern.get_vulnerability()
            for pattern in self.patterns
            if pattern.has_source(source)
        ]

    def get_vulnerabilities_with_sanitizer(
        self, sanitizer: Sanitizer
    ) -> Set[Vulnerability]:
        return [
            pattern.get_vulnerability()
            for pattern in self.patterns
            if pattern.has_sanitizer(sanitizer)
        ]

    def get_vulnerabilities_with_sink(self, sink: Sink) -> Set[Vulnerability]:
        return [
            pattern.get_vulnerability()
            for pattern in self.patterns
            if pattern.has_sink(sink)
        ]

    def get_illegal_flows(self, sink: Sink, multilabel: MultiLabel) -> MultiLabel:
        new_mapping = {}

        for pattern in multilabel.get_patterns():
            if pattern.has_sink(sink):
                new_mapping[pattern] = multilabel.get_label(pattern)

        return MultiLabel(new_mapping)
