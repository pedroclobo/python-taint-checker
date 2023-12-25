import ast
from typing import Set

from domain.MultiLabel import MultiLabel
from domain.Variable import Variable
from domain.Vulnerabilities import Vulnerabilities

from visitors.NodeLabeler import NodeLabeler


class NodeProcessor(ast.NodeVisitor):
    def __init__(
        self, vulnerabilities: Vulnerabilities, uninitialized_variables: Set[Variable]
    ):
        self.vulnerabilities = vulnerabilities
        self.uninitialized_variables = uninitialized_variables

    def visit(self, node):
        method_name = "visit_" + node.__class__.__name__
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        print(f"Processing generic visit for {node.__class__.__name__}")

    # Entry point
    def visit_Module(self, node):
        print(ast.dump(node, indent=2))
        for child in node.body:
            self.visit(child)

    def visit_Constant(self, node):
        pass

    def visit_Name(self, node):

        # add multi-label
        nodeLabel = NodeLabeler(self.vulnerabilities, self.uninitialized_variables)
        self.vulnerabilities.add_multi_label(nodeLabel.visit(node), node.id)

    def visit_BinOp(self, node):
        self.visit(node.left)
        self.visit(node.right)

    def visit_UnaryOp(self, node):
        raise NotImplementedError

    def visit_BoolOp(self, node):
        raise NotImplementedError

    def visit_Compare(self, node):
        raise NotImplementedError

    def visit_Call(self, node):
        self.visit(node.func)
        for arg in node.args:
            self.visit(arg)

        # combine multi-labels of function arguments
        node_label = NodeLabeler(self.vulnerabilities, self.uninitialized_variables)
        args_multi_label = MultiLabel()
        for arg in node.args:
            args_multi_label = args_multi_label.combine(node_label.visit(arg))

        func_multi_label = self.vulnerabilities.get_multi_label(node.func.id)
        func_multi_label = func_multi_label.combine(args_multi_label)

        # add sanitizers
        for pattern in self.vulnerabilities.get_patterns():
            if pattern.has_sanitizer(node.func.id):
                label = func_multi_label.get_label(pattern)
                for source, _ in label.get_sources():
                    label.add_sanitizer(node.func.id, node.lineno, source)

        # add sinks
        for pattern in self.vulnerabilities.get_patterns():
            if pattern.has_sink(node.func.id) and isinstance(node.func.ctx, ast.Load):
                self.vulnerabilities.add_sink(pattern, node.func.id, node.func.lineno)

        self.vulnerabilities.add_multi_label(func_multi_label, node.func.id)

    def visit_Attribute(self, node):
        raise NotImplementedError

    def visit_Expr(self, node):
        self.visit(node.value)

    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)

        node_label = NodeLabeler(self.vulnerabilities, self.uninitialized_variables)
        value_multi_label = node_label.visit(node.value)

        # combine multi-label of values with targets
        for target in node.targets:
            target_multi_label = node_label.visit(target)
            value_multi_label = value_multi_label.combine(target_multi_label)
            self.vulnerabilities.add_multi_label(
                target_multi_label.combine(value_multi_label), target.id
            )

        # add sinks
        for pattern in self.vulnerabilities.get_patterns():
            for target in node.targets:
                if pattern.has_sink(target.id):
                    self.vulnerabilities.add_sink(pattern, target.id, target.lineno)

    def visit_If(self, node):
        raise NotImplementedError

    def visit_While(self, node):
        raise NotImplementedError
