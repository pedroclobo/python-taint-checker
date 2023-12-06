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
        print(ast.dump(node, indent=2) + "\n")
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
        raise NotImplementedError

    def visit_Attribute(self, node):
        raise NotImplementedError

    def visit_Expr(self, node):
        raise NotImplementedError

    # TODO: support multiple targets
    def visit_Assign(self, node):
        for pattern in self.vulnerabilities.get_patterns():
            target = node.targets[0].id

            # add label for variable
            self.vulnerabilities.add_label(pattern, target)

            if isinstance(node.value, ast.Constant):
                pass  # nothing to do
            elif isinstance(node.value, ast.Call):
                func_name = node.value.func.id

                if pattern.has_source(func_name):
                    print("sdjkadsjkdjaskda")
                    print("sdjkadsjkdjaskda")
                    print("sdjkadsjkdjaskda")
                    print("sdjkadsjkdjaskda")
                    print("sdjkadsjkdjaskda")
                    self.vulnerabilities.add_label_with_source(pattern, target, func_name)

                print(self.vulnerabilities)

            else:
                print(f"Unsupported node type: {node.value.__class__.__name__}")
                raise NotImplementedError

    def visit_If(self, node):
        raise NotImplementedError

    def visit_While(self, node):
        raise NotImplementedError