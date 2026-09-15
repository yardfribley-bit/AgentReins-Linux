# Third-Party Notices

AgentReins Linux integrates with open-source runtime security components, including KubeArmor, which is distributed under the Apache License 2.0.

KubeArmor copyright and license information is available from its upstream project:

- <https://github.com/kubearmor/KubeArmor>
- <https://www.apache.org/licenses/LICENSE-2.0>

AgentReins names, correlation logic, evidence model, collectors, presentation, and product behavior are separate from those upstream projects. When third-party source or binaries are redistributed, their original copyright and license files must accompany that distribution.

## AgentSpec

The compatibility grammar under `policy/agentspec/AgentSpec.g4` originates from
`haoyuwang99/AgentSpec` and is included with authorization from the rights holder.
AgentReins Policy IR, natural-language compilation, validation, host-runtime
adapters, and enforcement orchestration are AgentReins additions.

- <https://github.com/haoyuwang99/AgentSpec>
- Haoyu Wang, Christopher M. Poskitt, and Jun Sun, “AgentSpec: Customizable
  Runtime Enforcement for Safe and Reliable LLM Agents” (2025).
