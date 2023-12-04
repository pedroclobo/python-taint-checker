from typing import Dict, Set

from domain.Sanitizer import Sanitizer
from domain.Source import Source


class Label:
    """
    Represents the integrity of information that is carried by a resource.

    Captures the sources that might have influenced a certain piece of
    information, and which sanitizers might have intercepted the information
    since its flow from each source.
    """

    def __init__(self):
        self.sources = set()
        self.sanitizers = {}

    def __init__(self, sources: Set[Source], sanitizers: Dict[Source, Set[Sanitizer]]):
        self.sources = sources
        self.sanitizers = sanitizers

    def get_sources(self) -> Set[Source]:
        return self.sources

    def add_source(self, source: Source):
        self.sources.append(source)
        self.sanitizers[source] = []

    def get_sanitizers(self) -> Dict[Source, Set[Sanitizer]]:
        return self.sanitizers

    def add_sanitizer_for_source(self, sanitizer: Sanitizer, source: Source):
        self.sanitizers[source].append(sanitizer)

    def combine(self, other: "Label"):
        """
        Return a new Label with the union of the sources and sanitizers of the two labels.
        """
        return Label(
            self.sources.union(other.get_sources()),
            {**self.sanitizers, **other.get_sanitizers()},
        )
