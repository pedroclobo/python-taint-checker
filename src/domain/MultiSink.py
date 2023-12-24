import json

from typing import Dict, List, Set, Tuple

from domain.Pattern import Pattern
from domain.Sink import Sink
from domain.Variable import Variable


class MultiSink:
    def __init__(self) -> None:
        self.mapping: Dict[Pattern, Set[Tuple[Sink, int]]] = {}

    def get_mapping(
        self,
    ) -> Dict[Pattern, Set[Tuple[Sink, int]]]:
        return self.mapping

    def get_patterns(self) -> Set[Pattern]:
        return set(self.mapping.keys())

    def has_pattern(self, pattern: Pattern) -> bool:
        return pattern in self.mapping

    def get_sinks(self, pattern: Pattern) -> List[Tuple[Sink, int]]:
        if not self.has_pattern(pattern):
            return []
        return sorted(list(self.mapping[pattern]), key=lambda sink: sink[1])

    def is_sink(self, pattern: Pattern, sink: Sink) -> bool:
        if self.has_pattern(pattern):
            for s, _ in self.mapping[pattern]:
                if s == sink:
                    return True

        return False

    def get_lineno(self, pattern: Pattern, sink: Sink) -> int:
        """
        Returns the smallest line number in the file
        """
        linenos = []

        if self.has_pattern(pattern):
            for s, lineno in self.mapping[pattern]:
                if s == sink:
                    linenos += [lineno]

        if len(linenos) == 0:
            return -1
        else:
            return min(linenos)

    def add_sink(
        self,
        pattern: Pattern,
        sink: Sink,
        lineno: int,
    ) -> None:
        if pattern not in self.mapping:
            self.mapping[pattern] = set()
        self.mapping[pattern].add((sink, lineno))

    def to_json(self):
        return {
            "mapping": [
                (
                    pattern.to_json(),
                    [
                        (
                            sink,
                            lineno,
                        )
                        for (sink, lineno) in sinks
                    ],
                )
                for pattern, sinks in self.mapping.items()
            ]
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
