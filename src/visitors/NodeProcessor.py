import ast
from typing import Set
from domain.Flow import Flow
from domain.IllegalFlow import IllegalFlow

from domain.Variable import Variable
from domain.Vulnerabilities import Vulnerabilities

from visitors.NodeLabeler import NodeLabeler
from visitors.UninitializedVariableDetector import UninitializedVariableDetector


class NodeProcessor(ast.NodeVisitor):
    def __init__(
        self,
        vulnerabilities: Vulnerabilities,
        uninitialized_variable_detector: UninitializedVariableDetector,
    ):
        self.vulnerabilities = vulnerabilities
        self.uninitialized_variable_detector = uninitialized_variable_detector

    def visit_Name(self, node):
        # add multi-label
        nodeLabel = NodeLabeler(
            self.vulnerabilities, self.uninitialized_variable_detector
        )
        self.vulnerabilities.add_multi_label(nodeLabel.visit(node), node.id)

    def visit_Call(self, node):
        self.visit(node.func)
        for arg in node.args:
            self.visit(arg)

        node_labeler = NodeLabeler(
            self.vulnerabilities, self.uninitialized_variable_detector
        )
        func_multi_label = node_labeler.visit(node)

        if isinstance(node.func, ast.Name):
            func_id = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_id = node.func.attr
        else:
            raise NotImplementedError

        # add sinks
        for pattern in self.vulnerabilities.get_patterns():
            if pattern.has_sink(func_id):
                label = func_multi_label.get_label(pattern)
                for source, source_lineno in label.get_sources():
                    if node.func.id == source:
                        continue
                    flows = list(label.get_flows_from_source(source))
                    if len(flows) == 0:
                        continue
                    self.vulnerabilities.add_illegal_flow(
                        IllegalFlow(
                            pattern.get_vulnerability(),
                            source,
                            source_lineno,
                            func_id,
                            node.lineno,
                            Flow() in flows,
                            [] if len(flows) == 0 else flows,
                        )
                    )

    def visit_Attribute(self, node):
        nodeLabel = NodeLabeler(
            self.vulnerabilities, self.uninitialized_variable_detector
        )
        self.vulnerabilities.add_multi_label(
            nodeLabel.visit(node), node.value.id + "." + node.attr
        )

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)

        # the multi-labels of the targets are the labels of the value
        node_label = NodeLabeler(
            self.vulnerabilities, self.uninitialized_variable_detector
        )
        value_multi_label = node_label.visit(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_id = target.id
            elif isinstance(target, ast.Attribute):
                target_id = target.value.id + "." + target.attr
            else:
                raise NotImplementedError
            self.vulnerabilities.add_multi_label(value_multi_label, target_id)

        # add sinks
        for pattern in self.vulnerabilities.get_patterns():
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if pattern.has_sink(target.id):
                        label = self.vulnerabilities.get_multi_label(
                            target_id
                        ).get_label(pattern)
                        for source, source_lineno in label.get_sources():
                            if target_id == source:
                                continue
                            flows = list(label.get_flows_from_source(source))
                            if len(flows) == 0:
                                continue
                            self.vulnerabilities.add_illegal_flow(
                                IllegalFlow(
                                    pattern.get_vulnerability(),
                                    source,
                                    source_lineno,
                                    target_id,
                                    node.lineno,
                                    Flow() in flows,
                                    [] if len(flows) == 0 else flows,
                                )
                            )
                elif isinstance(target, ast.Attribute):
                    if pattern.has_sink(target.value.id) or pattern.has_sink(
                        target.attr
                    ):
                        label = self.vulnerabilities.get_multi_label(
                            target.value.id + "." + target.attr
                        ).get_label(pattern)
                        for source, source_lineno in label.get_sources():
                            flows = list(label.get_flows_from_source(source))
                            if len(flows) == 0:
                                continue
                            target_id = (
                                target.value.id
                                if pattern.has_sink(target.value.id)
                                else target.attr
                            )
                            self.vulnerabilities.add_illegal_flow(
                                IllegalFlow(
                                    pattern.get_vulnerability(),
                                    source,
                                    source_lineno,
                                    target_id,
                                    node.lineno,
                                    Flow() in flows,
                                    [] if len(flows) == 0 else flows,
                                )
                            )

    def visit_If(self, node):
        raise NotImplementedError

    def visit_While(self, node):
        raise NotImplementedError
