from typing import Dict, Set, Tuple

from domain.Pattern import Pattern
from domain.Sink import Sink
from domain.Variable import Variable


class MultiSink:
    def __init__(self) -> None:
        self.mapping: Dict[Pattern, Dict[Tuple[Sink, int], Set[Variable]]] = {}

    def get_mapping(self) -> Dict[Pattern, Dict[Tuple[Sink, int], Set[Variable]]]:
        return self.mapping

    def get_patterns(self) -> Set[Pattern]:
        return set(self.mapping.keys())

    def get_sinks(self, pattern: Pattern) -> Set[Tuple[Sink, int]]:
        if pattern not in self.mapping:
            return set()
        return set(self.mapping[pattern].keys())

    def is_variable_in_sink(
        self, pattern: Pattern, sink: Sink, lineno: int, variable: Variable
    ) -> bool:
        if pattern not in self.mapping:
            return False
        return (sink, lineno) in self.mapping[pattern] and variable in self.mapping[
            pattern
        ][(sink, lineno)]

    def add_sink(
        self, pattern: Pattern, sink: Sink, lineno: int, variable: Variable
    ) -> None:
        if pattern not in self.mapping:
            self.mapping[pattern] = {}
        if (sink, lineno) not in self.mapping[pattern]:
            self.mapping[pattern][(sink, lineno)] = set(variable)
        else:
            old_variables = self.mapping[pattern][(sink, lineno)]
            self.mapping[pattern][(sink, lineno)] = old_variables.union(set(variable))
