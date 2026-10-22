#!/usr/bin/env python3
"""Report which alert rules stay off because the deploy config is still empty.

Read-only. Exit 0. The drill template is expected to report S14, S15, S22,
S02, and I1 as disabled until an operator fills them in.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.agents_config import load_agents

APPLICATION_ROLES = ('web', 'api', 'worker', 'plugin', 'sandbox')
S22_ROLES = ('web', 'api')


def _runtime_config(path):
    if not path:
        return {}
    file = Path(path)
    if not file.is_file():
        return {}
    try:
        data = json.loads(file.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _roles(agent):
    found = []
    for item in agent.get('containerRoles') or []:
        role = item.get('role')
        if role and role not in found:
            found.append(role)
    return found


def report(agents, runtime_config=None):
    runtime_config = runtime_config or {}
    lines = []
    thresholds = runtime_config.get('toolThresholds')
    if isinstance(thresholds, dict) and any(int(thresholds.get(key) or 0) > 0 for key in ('perMinute', 'perChainTool')):
        lines.append('runtime S15 enabled: perMinute=%s perChainTool=%s' % (thresholds.get('perMinute', 0), thresholds.get('perChainTool', 0)))
    else:
        lines.append('runtime S15 disabled: toolThresholds is not set in the runtime config')
    for agent in agents or []:
        agent_id = agent.get('id') or '?'
        tools = agent.get('allowedTools') or []
        if tools:
            lines.append('%s S14 enabled: %d allowedTools' % (agent_id, len(tools)))
        else:
            lines.append('%s S14 disabled: allowedTools is empty' % agent_id)
        networks = agent.get('allowedNetworks') or []
        if networks:
            lines.append('%s S05 enabled: allowedNetworks is set' % agent_id)
            lines.append('%s S02 enabled: allowedNetworks is set; an alert still needs an untrusted segment and an exact host match' % agent_id)
        else:
            lines.append('%s S05 disabled: allowedNetworks is empty' % agent_id)
            lines.append('%s S02 disabled: allowedNetworks is empty, so an out-of-allowlist destination is not evaluated' % agent_id)
        servers = agent.get('webServers') or []
        roles = _roles(agent)
        if servers and any(role in S22_ROLES for role in roles):
            lines.append('%s S22 enabled: %s' % (agent_id, ','.join(servers)))
        elif not servers:
            lines.append('%s S22 disabled: webServers is empty' % agent_id)
        else:
            lines.append('%s S22 disabled: webServers is set but no web or api container role' % agent_id)
        if any(role in APPLICATION_ROLES for role in roles):
            lines.append('%s S20 enabled: container role %s' % (agent_id, ','.join(roles)))
        else:
            lines.append('%s S20 disabled: no web, api, worker, plugin, or sandbox container role' % agent_id)
        if agent.get('knowledgeMarkers'):
            lines.append('%s I1 enabled: knowledgeMarkers is set' % agent_id)
        else:
            lines.append('%s I1 disabled: knowledgeMarkers is unset' % agent_id)
        baseline = agent.get('toolDefinitionBaseline') or {}
        pinned = baseline.get('pinned') or {}
        lines.append('%s S23 enabled: learnRequests=%s learnSeconds=%s pinned=%d' % (
            agent_id, baseline.get('learnRequests', 10), baseline.get('learnSeconds', 600), len(pinned),
        ))
        allow = (agent.get('gateway') or {}).get('peerAllowlist') or []
        if allow:
            lines.append('%s gateway enabled: peerAllowlist has %d entries' % (agent_id, len(allow)))
        else:
            lines.append('%s gateway warning: peerAllowlist is empty, so every peer is accepted' % agent_id)
    return '\n'.join(lines) + ('\n' if lines else '')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Report rules left disabled by missing config')
    parser.add_argument('--agents', required=True, help='agents.yaml path')
    parser.add_argument('--runtime-config', help='runtime config.json path')
    args = parser.parse_args(argv)
    agents = load_agents(args.agents)
    text = report(agents, _runtime_config(args.runtime_config))
    sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
