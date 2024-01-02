import ast
from typing import Tuple


class IfTransformer(ast.NodeTransformer):

    def __init__(self, branches: Tuple[bool]) -> None:
        self.branches = branches
        self.index = 0

    def visit_If(self, node):
        true_stmt = list(map(lambda stmt: self.visit(stmt) if isinstance(stmt, ast.If) else stmt, node.body))
        false_stmt = list(map(lambda stmt: self.visit(stmt) if isinstance(stmt, ast.If) else stmt, node.orelse))

        if self.branches[self.index]:
            self.index += 1
            return ast.Module(true_stmt)
        else:
            self.index += 1
            return ast.Module(false_stmt)

    def visit_While(self, node):
        raise NotImplementedError
