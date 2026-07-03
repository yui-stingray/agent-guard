# Fixture Repository

agent-guard surface inventory --root . --context-policy .agent-guard/context-policy.yaml
agent-guard context check --root . --policy .agent-guard/context-policy.yaml
agent-guard workflow check --root . --policy .agent-guard/workflow-policy.yaml
agent-guard drift check --root .
agent-guard report --root . --context-policy .agent-guard/context-policy.yaml
