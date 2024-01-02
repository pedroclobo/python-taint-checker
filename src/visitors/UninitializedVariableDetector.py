import ast
from typing import Dict, Set

from domain.Variable import Variable


class UninitializedVariableDetector(ast.NodeVisitor):
    """
    Searches for uninitialized variables

    Functions and attributes are considered initialized
    """

    def __init__(self) -> None:
        self.variables: Set[Variable] = set()
        self.initialized: Dict[Variable, int] = dict()

    def is_initialized(self, variable: Variable, lineno: int) -> bool:
        if variable in self.initialized:
            return self.initialized[variable] <= lineno
        return False

    def is_uninitialized(self, variable: Variable, lineno: int) -> bool:
        return not self.is_initialized(variable, lineno)

    def add_initialized(self, variable: Variable, lineno: int) -> None:
        assert variable in self.variables
        if variable not in self.initialized:
            self.initialized[variable] = lineno
        self.initialized[variable] = min(self.initialized[variable], lineno)

    def visit(self, node):
        method_name = "visit_" + node.__class__.__name__
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        print(f"Processing generic visit for {node.__class__.__name__}")

    def visit_Module(self, node):
        for child in node.body:
            self.visit(child)

    def visit_Constant(self, node):
        return

    def visit_Name(self, node):
        self.variables.add(node.id)

        if isinstance(node.ctx, ast.Store):
            self.add_initialized(node.id, node.lineno)

    def visit_BinOp(self, node):
        self.visit(node.left)
        self.visit(node.right)

    def visit_UnaryOp(self, node):
        self.visit(node.operand)

    def visit_BoolOp(self, node):
        for child in node.values:
            self.visit(child)

    def visit_Compare(self, node):
        self.visit(node.left)
        for child in node.comparators:
            self.visit(child)

    def visit_Call(self, node):
        self.visit(node.func)

        # mark function as initialized
        if isinstance(node.func, ast.Name):
            self.add_initialized(node.func.id, node.lineno)

        for arg in node.args:
            self.visit(arg)

    def visit_Attribute(self, node):
        self.visit(node.value)

        # attributes are always initialized
        self.variables.add(node.attr)
        self.add_initialized(node.attr, node.lineno)

    def visit_Expr(self, node):
        self.visit(node.value)

    def visit_Assign(self, node):
        for target in node.targets:
            self.visit(target)

        self.visit(node.value)

    def visit_If(self, node):
        self.visit(node.test)
        for child in node.body:
            self.visit(child)
        for child in node.orelse:
            self.visit(child)
        # raise NotImplementedError

    def visit_While(self, node):
        self.visit(node.test)
        for child in node.body:
            self.visit(child)
        for child in node.orelse:
            self.visit(child)
