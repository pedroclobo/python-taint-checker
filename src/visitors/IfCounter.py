import ast


class IfCounter(ast.NodeVisitor):

    def __init__(self):
        self.counter = 0

    def get_count(self):
        return self.counter

    def visit_If(self, node):
        self.counter += 1
        for stmt in node.body:
            self.visit(stmt)
