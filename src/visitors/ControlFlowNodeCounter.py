import ast


class ControlFlowNodeCounter(ast.NodeVisitor):

    def __init__(self):
        self.node_types = []
        self.if_counter = 0
        self.while_counter = 0

    def get_if_count(self):
        return self.if_counter

    def get_while_count(self):
        return self.while_counter

    def get_count(self):
        return self.if_counter + self.while_counter

    def get_node_types(self):
        return self.node_types

    def visit_If(self, node):
        self.node_types += [ast.If]

        self.if_counter += 1
        for stmt in node.body:
            self.visit(stmt)

    def visit_While(self, node):
        self.node_types += [ast.While]

        self.while_counter += 1
        for stmt in node.body:
            self.visit(stmt)
