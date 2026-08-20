from secure_agent_harness.contracts import ToolCallProposal
from secure_agent_harness.policy import authorize


def test_approval_cannot_add_a_missing_mutation_capability() -> None:
    decision = authorize(
        ToolCallProposal(
            tool_name="patch_instance",
            arguments={"resource_id": "EC2_RESOURCE_01"},
        )
    )

    assert decision.allowed is False
    assert decision.requires_approval is True
