import ast
from typing import Set

from domain.Variable import Variable


class UninitializedVariableDetector(ast.NodeVisitor):
    """
    Searches for uninitialized variables
    """

    def __init__(self):
        self.variables: Set[Variable] = set()
        self.initialized: Set[Variable] = set()

    def get_uninitialized_variables(self) -> Set[Variable]:
        return self.variables - self.initialized

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
            self.initialized.add(node.id)

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
        self.initialized.add(node.func.id) # function are considered to be initialized

        for arg in node.args:
            self.visit(arg)

    def visit_Attribute(self, node):
        raise NotImplementedError

    def visit_Expr(self, node):
        self.visit(node.value)

    def visit_Assign(self, node):
        for target in node.targets:
            self.visit(target)

        self.visit(node.value)

    def visit_If(self, node):
        raise NotImplementedError

    def visit_While(self, node):
        raise NotImplementedError
