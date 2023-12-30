import json

from typing import Dict, Set, Tuple

from domain.Pattern import Pattern
from domain.Sink import Sink


class MultiSink:
    def __init__(self) -> None:
        self.mapping: Dict[Pattern, Set[Tuple[Sink, int]]] = {}

    def get_patterns(self) -> Set[Pattern]:
        return set(self.mapping.keys())

    def has_pattern(self, pattern: Pattern) -> bool:
        return pattern in self.mapping

    def get_sinks(self, pattern: Pattern) -> Set[Tuple[Sink, int]]:
        if not self.has_pattern(pattern):
            return set()
        return self.mapping[pattern]

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
