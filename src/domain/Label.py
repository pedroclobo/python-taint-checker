import json

from typing import Dict, Set, Tuple

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
        sources: Set[Tuple[Source, int]] = set(),
        sanitizers: Set[Tuple[Sanitizer, int]] = set(),
    ) -> None:
        self.sources = sources
        self.sanitizers = sanitizers

    def get_sources(self) -> Set[Tuple[Source, int]]:
        return self.sources

    def add_source(self, source: Source, lineno: int) -> None:
        self.sources.add((source, lineno))

    def get_sanitizers(self) -> Set[Tuple[Sanitizer, int]]:
        return self.sanitizers

    def add_sanitizer(self, sanitizer: Sanitizer, lineno: int) -> None:
        self.sanitizers.add((sanitizer, lineno))

    def combine(self, other: "Label") -> "Label":
        """
        Return a new Label with the union of the sources and sanitizers of the 
        two labels.
        """
        combined_sources = self.get_sources().union(other.get_sources())
        combined_sanitizers = self.get_sanitizers().union(other.get_sanitizers())

        return Label(combined_sources, combined_sanitizers)

    def to_json(self) -> Dict:
        return {
            "sources": [source for source in self.get_sources()],
            "sanitizers": [sanitizer for sanitizer in self.get_sanitizers()],
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)
