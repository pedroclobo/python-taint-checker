from typing import Set

from domain.Sanitizer import Sanitizer
from domain.Sink import Sink
from domain.Source import Source
from domain.Vulnerability import Vulnerability

import json


class Pattern:
    def __init__(
        self,
        vulnerability: Vulnerability,
        sources: Set[Source],
        sanitizers: Set[Sanitizer],
        sinks: Set[Sink],
        implicit: bool,
    ):
        self.vulnerability = vulnerability
        self.sources = sources
        self.sanitizers = sanitizers
        self.sinks = sinks
        self.implicit = implicit

    def get_vulnerability(self) -> Vulnerability:
        return self.vulnerability

    def get_sources(self) -> Set[Source]:
        return self.sources

    def has_source(self, source: Source) -> bool:
        return source in self.sources

    def get_sanitizers(self) -> Set[Sanitizer]:
        return self.sanitizers

    def has_sanitizer(self, sanitizer: Sanitizer) -> bool:
        return sanitizer in self.sanitizers

    def get_sinks(self) -> Set[Sink]:
        return self.sinks

    def has_sink(self, sink: Sink) -> bool:
        return sink in self.sinks

    def consider_implicit(self) -> bool:
        return self.implicit

    @classmethod
    def from_json(cls, json_data):
        vulnerability = Vulnerability(json_data["vulnerability"])
        sources = {Source(source) for source in json_data["sources"]}
        sinks = {Sink(sink) for sink in json_data["sinks"]}
        sanitizers = {
            Sanitizer(sanitizer) for sanitizer in json_data.get("sanitizers", [])
        }
        implicit = json_data.get("implicit", False)

        return cls(vulnerability, sources, sanitizers, sinks, implicit)

    def __repr__(self):
        return (
            "Pattern {\n"
            + f"\tvulnerability: {self.vulnerability},\n"
            + f"\tsources: {self.sources},\n"
            + f"\tsanitizers: {self.sanitizers},\n"
            + f"\tsinks: {self.sinks},\n"
            + f"\timplicit: {self.implicit}\n"
            + "}"
        )
