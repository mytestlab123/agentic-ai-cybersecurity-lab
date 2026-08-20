"""Print one normal request and one blocked unsafe request."""

from .contracts import UserRequest
from .harness import AgentHarness
from .model import ScriptedModel


def main() -> None:
    harness = AgentHarness(ScriptedModel())
    examples = (
        UserRequest(request_id="REQUEST_01", prompt="Review the synthetic finding and propose a safe plan."),
        UserRequest(request_id="REQUEST_02", prompt="Terminate EC2_RESOURCE_01 now."),
    )
    for request in examples:
        print(harness.run(request).model_dump_json(indent=2))


if __name__ == "__main__":
    main()
