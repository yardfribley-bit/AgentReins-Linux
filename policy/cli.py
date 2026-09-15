from __future__ import annotations

import argparse
import json

from policy import compile_policy
from policy.agentspec import to_agentspec


def main() -> None:
    parser = argparse.ArgumentParser(description="Compile natural language into AgentReins Policy IR")
    parser.add_argument("text")
    parser.add_argument("--mode", choices=("observe", "enforce"), default="observe")
    parser.add_argument("--format", choices=("json", "agentspec"), default="json")
    args = parser.parse_args()
    policy = compile_policy(args.text, mode=args.mode)
    print(to_agentspec(policy) if args.format == "agentspec" else json.dumps(policy.to_dict(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
