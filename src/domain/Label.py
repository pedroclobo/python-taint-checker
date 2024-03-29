from copy import deepcopy
import json

from typing import Dict, Set, Tuple
from domain.Flow import Flow

from domain.Sanitizer import Sanitizer
from domain.Source import Source


class Label:
    """
    Represents the integrity of information that is carried by a resource.

    Captures the sources that might have influenced a certain piece of
    information, and which sanitizers might have intercepted the information
    since its flow from each source.
    """

    def __init__(self) -> None:
        self.sources: Set[Tuple[Source, int]] = set()
        self.flows: Dict[Source, Set[Flow]] = dict()

    def get_sources(self) -> Set[Tuple[Source, int]]:
        return self.sources

    def add_source(self, source: Source, lineno: int) -> None:
        self.sources.add((source, lineno))
        flow = Flow()
        self.flows[source] = {flow}

    def get_flows_from_source(self, source: Source) -> Set[Flow]:
        if source not in self.flows:
            return set()
        return self.flows[source]

    def add_sanitizer(self, sanitizer: Sanitizer, lineno: int, source: Source) -> None:
        if source not in self.flows:
            flow = Flow()
            self.flows[source] = {flow}

        for flow in self.flows[source]:
            flow.add_sanitizer(sanitizer, lineno)

    def combine(self, other: "Label") -> "Label":
        """
        Return a new Label with the union of the sources and sanitizers of the
        two labels.
        """
        combined_sources = self.sources.union(other.sources)
        combined_flows = {}

        for source, _ in combined_sources:
            self_flows = deepcopy(self.get_flows_from_source(source))
            other_flows = deepcopy(other.get_flows_from_source(source))
            combined_flows[source] = self_flows.union(other_flows)

        label = Label()
        label.sources = combined_sources
        label.flows = combined_flows

        return label

    def to_json(self) -> Dict:
        return {
            "sources": [source for source in self.sources],
            "flows": {
                source: [flow.to_json() for flow in self.flows[source]]
                for source in self.flows
            },
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json(), indent=2)

    def __eq__(self, other) -> bool:
        return self.sources == other.sources and self.flows == other.flows
