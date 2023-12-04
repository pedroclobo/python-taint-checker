from domain.MultiLabelling import MultiLabelling
from domain.Policy import Policy


class Vulnerabilities:
    """
    Collects all the illegal information flows discovered during the execution
    of the slice.
    """

    def __init__(self, policy: Policy, multilabelling: MultiLabelling):
        self.policy = policy
        self.multilabelling = multilabelling

    def get_policy(self) -> Policy:
        return self.policy

    def get_multi_labelling(self) -> MultiLabelling:
        return self.multilabelling

    # TODO
