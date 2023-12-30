import json

from typing import Dict, List, Set, Tuple

from domain.Sanitizer import Sanitizer
from domain.Source import Source


class Label:
    """
    Represents the integrity of information that is carried by a resource.

    Captures the sources that might have influenced a certain piece of
    information, and which sanitizers might have intercepted the information
    since its flow from each source.
    """

    def __init__(
        self,
            sources=None,
            sanitizers=None,
    ) -> None:
        if sanitizers is None:
            sanitizers = dict()
        if sources is None:
            sources = set()
        self.sources = sources
        self.sanitizers = sanitizers

    def get_sources(self) -> Set[Tuple[Source, int]]:
        return self.sources

    def add_source(self, source: Source, lineno: int) -> None:
        self.sources.add((source, lineno))

    def get_sanitizers_for_source(self, source: Source) -> Set[Tuple[Sanitizer, int]]:
        if source not in self.sanitizers:
            return set()
        return self.sanitizers[source]

    def add_sanitizer(self, sanitizer: Sanitizer, lineno: int, source: Source) -> None:
        if source not in self.sanitizers:
            self.sanitizers[source] = set()

        self.sanitizers[source].add((sanitizer, lineno))

    def combine(self, other: "Label") -> "Label":
        """
        Return a new Label with the union of the sources and sanitizers of the
        two labels.
        """
        combined_sources = self.sources.union(other.sources)
        combined_sanitizers = self.sanitizers.copy()

        for source in other.sanitizers:
            sanitizers = other.sanitizers[source]
            if source in combined_sanitizers:
                combined_sanitizers[source] = combined_sanitizers[source].union(
                    sanitizers
                )
            else:
                combined_sanitizers[source] = sanitizers

        return Label(combined_sources, combined_sanitizers)

    def to_json(self) -> Dict:
        return {
            "sources": [source for source in self.sources],
            "sanitizers": {
                str(source): [sanitizer for sanitizer in sanitizers]
                for source, sanitizers in self.sanitizers.items()
            },
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
