import ast
from typing import Tuple


class ControlFlowTransformer(ast.NodeTransformer):

    def __init__(self, branches: Tuple[Tuple[bool, int]]) -> None:
        self.branches = branches
        self.index = 0

    def visit_If(self, node):
        true_stmt = list(map(lambda stmt: self.visit(stmt) if isinstance(stmt, ast.If) else stmt, node.body))
        false_stmt = list(map(lambda stmt: self.visit(stmt) if isinstance(stmt, ast.If) else stmt, node.orelse))

        branch, _ = self.branches[self.index]

        if branch:
            self.index += 1
            return ast.Module(true_stmt)
        else:
            self.index += 1
            return ast.Module(false_stmt)

    def visit_While(self, node):
        true_stmt = list(map(lambda stmt: self.visit(stmt) if isinstance(stmt, ast.If) else stmt, node.body))
        false_stmt = list(map(lambda stmt: self.visit(stmt) if isinstance(stmt, ast.If) else stmt, node.orelse))

        branch, repeat = self.branches[self.index]

        if branch:
            self.index += 1
            return ast.Module(true_stmt * repeat)
        else:
            self.index += 1
            return ast.Module(false_stmt)
