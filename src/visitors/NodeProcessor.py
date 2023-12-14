import ast

from domain.Vulnerabilities import Vulnerabilities


class NodeProcessor(ast.NodeVisitor):
    def __init__(self, vulnerabilities: Vulnerabilities):
        self.vulnerabilities = vulnerabilities

    def visit(self, node):
        method_name = "visit_" + node.__class__.__name__
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)

    def generic_visit(self, node):
        print(f"Processing generic visit for {node.__class__.__name__}")

    # Entry point
    def visit_Module(self, node):
        # print(ast.dump(node, indent=2))
        for child in node.body:
            self.visit(child)

    def visit_Constant(self, node):
        raise NotImplementedError

    def visit_Name(self, node):
        raise NotImplementedError

    def visit_BinOp(self, node):
        raise NotImplementedError

    def visit_UnaryOp(self, node):
        raise NotImplementedError

    def visit_BoolOp(self, node):
        raise NotImplementedError

    def visit_Compare(self, node):
        raise NotImplementedError

    def visit_Call(self, node):
        for pattern in self.vulnerabilities.get_patterns():
            func_name = node.func.id

            if pattern.has_sink(func_name):
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        self.vulnerabilities.add_combined_label(arg.id, func_name)
                        self.vulnerabilities.add_sink(pattern, func_name, node.lineno)
                    elif isinstance(arg, ast.Constant):
                        pass

    def visit_Attribute(self, node):
        raise NotImplementedError

    def visit_Expr(self, node):
        self.visit(node.value)

    # TODO: support multiple targets
    def visit_Assign(self, node):
        for pattern in self.vulnerabilities.get_patterns():
            target_id = node.targets[0].id

            # nothing to do
            if isinstance(node.value, ast.Constant):
                pass

            # function could be a source
            elif isinstance(node.value, ast.Call):
                func_name = node.value.func.id

                if pattern.has_source(func_name):
                    self.vulnerabilities.add_source_to_label(
                        pattern, target_id, func_name, node.lineno
                    )

            # propagate label
            elif isinstance(node.value, ast.Name):
                if pattern.has_source(node.value.id):
                    self.vulnerabilities.add_source_to_label(
                        pattern, target_id, node.value.id, node.lineno
                    )
                if pattern.has_sink(target_id):
                    self.vulnerabilities.add_sink(pattern, target_id, node.lineno)
                source = node.value.id
                self.vulnerabilities.add_combined_label(source, target_id)

            else:
                print(f"Unsupported node type: {node.value.__class__.__name__}")
                raise NotImplementedError

    def visit_If(self, node):
        raise NotImplementedError

    def visit_While(self, node):
        raise NotImplementedError
