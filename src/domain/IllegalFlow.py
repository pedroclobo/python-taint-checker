import json

from typing import Dict, List
from domain.Flow import Flow

from domain.Vulnerability import Vulnerability
from domain.Source import Source
from domain.Sink import Sink


class IllegalFlow:
    def __init__(
        self,
        vulnerability: Vulnerability,
        source: Source,
        source_lineno: int,
        sink: Sink,
        sink_lineno: int,
        unsanitized_flows: bool,
        sanitized_flows: List[Flow],
    ) -> None:
        self.vulnerability = vulnerability
        self.source = source
        self.source_lineno = source_lineno
        self.sink = sink
        self.sink_lineno = sink_lineno
        self.unsanitized_flows = unsanitized_flows
        self.sanitized_flows = sanitized_flows

    def get_vulnerability(self) -> Vulnerability:
        return self.vulnerability

    def to_json(self) -> Dict:
        return {
            "vulnerability": str(self.vulnerability),
            "source": [str(self.source), self.source_lineno],
            "sink": [str(self.sink), self.sink_lineno],
            "unsanitized_flows": "yes" if self.unsanitized_flows else "no",
            "sanitized_flows": list(
                map(
                    lambda flow: flow.to_json(),
                    filter(lambda flow: not flow.is_empty(), self.sanitized_flows),
                )
            ),
        }

    def __repr__(self) -> str:
        return json.dumps(self.to_json())
