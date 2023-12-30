import ast

from typing import Set
from domain.Flow import Flow

from domain.Label import Label
from domain.MultiLabel import MultiLabel
from domain.Variable import Variable
from domain.Vulnerabilities import Vulnerabilities


class NodeLabeler(ast.NodeVisitor):
    """
    Returns the resulting multi-label of a node
    """

    def __init__(
        self,
        vulnerabilities: Vulnerabilities,
        uninitialized_variables: Set[Variable],
    ):
        self.vulnerabilities = vulnerabilities
        self.uninitialized_variables: Set[Variable] = uninitialized_variables

    def visit(self, node):
        method_name = "visit_" + node.__class__.__name__
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        print(f"Processing generic visit for {node.__class__.__name__}")

    def visit_Module(self, node):
        raise ValueError

    def visit_Constant(self, node):
        return MultiLabel()

    def visit_Name(self, node):
        multi_label = self.vulnerabilities.get_multi_label(node.id)

        # mark name as source
        for pattern in self.vulnerabilities.get_patterns():
            if (pattern.has_source(node.id) and isinstance(node.ctx, ast.Load)) or (
                node.id in self.uninitialized_variables
            ):
                label = Label()
                label.add_source(node.id, node.lineno)
                multi_label = multi_label.combine(MultiLabel({pattern: label}))

        return multi_label

    def visit_BinOp(self, node):
        return self.visit(node.left).combine(self.visit(node.right))

    def visit_UnaryOp(self, node):
        raise NotImplementedError

    def visit_BoolOp(self, node):
        raise NotImplementedError

    def visit_Compare(self, node):
        raise NotImplementedError

    def visit_Call(self, node):
        multi_label_func = self.visit(node.func)

        multi_label_args = MultiLabel()
        for arg in node.args:
            multi_label_args = multi_label_args.combine(self.visit(arg))

        if node.func.id == "e":
            print(f"multi_label_args: {multi_label_args}")

        # add sources
        for pattern in self.vulnerabilities.get_patterns():
            args_label = multi_label_args.get_label(pattern)
            label = multi_label_func.get_label(pattern)
            for source, lineno in args_label.get_sources():
                label.add_source(source, lineno)
                label.get_flows_from_source(source).remove(Flow())  # remove empty flow
            multi_label_func.add_label(label, pattern)

        # combine multi-label of function with multi-label of arguments
        multi_label_func = multi_label_func.combine(multi_label_args)

        # add sanitizers
        for pattern in self.vulnerabilities.get_patterns():
            label = multi_label_func.get_label(pattern)
            if pattern.has_sanitizer(node.func.id):
                for source, _ in label.get_sources():
                    label.add_sanitizer(node.func.id, node.lineno, source)
            multi_label_func.add_label(label, pattern)

        return multi_label_func

    def visit_Attribute(self, node):
        raise NotImplementedError

    def visit_Expr(self, node):
        return self.visit(node.value)

    def visit_Assign(self, node):
        raise NotImplementedError

    def visit_If(self, node):
        raise NotImplementedError

    def visit_While(self, node):
        raise NotImplementedError
