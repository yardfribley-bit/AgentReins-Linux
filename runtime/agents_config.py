"""Load agent route and container bindings.

Patterns follow the existing containerPatterns rule: a pattern that contains
regex metacharacters is a full-match regular expression. Otherwise `*` and `?`
are shell globs, so `pentagi-terminal-*` matches `pentagi-terminal-<flowId>`.
"""
import fnmatch
import ipaddress
import json
import re
from pathlib import Path

_REGEX_MARKS = ('.*', '^', '$', '(', '[', '|', '+', '{', '\\')


def pattern_match(pattern, name):
    if not pattern or not name:
        return False
    if any(mark in pattern for mark in _REGEX_MARKS):
        try:
            return re.fullmatch(pattern, name) is not None
        except re.error:
            return False
    return fnmatch.fnmatchcase(name, pattern)


def session_from_container(name):
    """PentAGI names the tool container pentagi-terminal-<flowId>, optionally prefixed."""
    if not name:
        return None
    match = re.search(r'(?:^|-)pentagi-terminal-(.+)$', name)
    return match.group(1) if match else None


def peer_allowed(peer, allowlist):
    if not allowlist:
        return True
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for item in allowlist:
        try:
            if ip in ipaddress.ip_network(str(item), strict=False):
                return True
        except ValueError:
            continue
    return False


def normalize_agent(raw):
    if not isinstance(raw, dict) or not raw.get('id'):
        raise ValueError('agent 需要 id')
    gateway = raw.get('gateway') or {}
    if not isinstance(gateway, dict):
        raise ValueError('gateway 必须是映射')
    containers = []
    for item in raw.get('containers') or []:
        if isinstance(item, str):
            containers.append(item)
        elif isinstance(item, dict) and item.get('pattern'):
            containers.append(str(item['pattern']))
    agent_id = str(raw['id'])
    port = gateway.get('port')
    return {
        'id': agent_id,
        'gateway': {
            'bind': str(gateway.get('bind') or '127.0.0.1'),
            'port': int(port) if port else None,
            'pathPrefix': str(gateway.get('pathPrefix') or ('/a/' + agent_id)).rstrip('/'),
            'peerAllowlist': [str(x) for x in (gateway.get('peerAllowlist') or [])],
        },
        'containers': containers,
        'allowedNetworks': raw.get('allowedNetworks') or [],
    }


def load_agents(path=None, data=None):
    if data is None:
        if not path:
            return []
        file = Path(path)
        if not file.is_file():
            return []
        text = file.read_text()
        stripped = text.lstrip()
        if str(path).endswith('.json') or stripped.startswith('{') or stripped.startswith('['):
            data = json.loads(text)
        else:
            data = parse_simple_yaml(text)
    if isinstance(data, list):
        data = {'agents': data}
    if not isinstance(data, dict):
        raise ValueError('agents 配置必须是映射或列表')
    return [normalize_agent(item) for item in (data.get('agents') or [])]


def agent_for_container(agents, name):
    for agent in agents or []:
        if any(pattern_match(pattern, name) for pattern in agent['containers']):
            return agent
    return None


def agent_by_id(agents, agent_id):
    for agent in agents or []:
        if agent['id'] == agent_id:
            return agent
    return None


def resolve_route(agents, path, port):
    """Return (agent, upstream_path, how) or (None, None, reason)."""
    if not path or '..' in path.split('/'):
        return None, None, 'reject'
    for agent in agents or []:
        prefix = agent['gateway']['pathPrefix']
        if path == prefix or path.startswith(prefix + '/'):
            rest = path[len(prefix):] or '/'
            if not rest.startswith('/'):
                rest = '/' + rest
            return agent, _upstream_path(rest), 'path'
    owners = [agent for agent in (agents or []) if agent['gateway']['port'] and int(agent['gateway']['port']) == int(port)]
    if len(owners) == 1 and (path.startswith('/v1/') or path == '/v1'):
        return owners[0], _upstream_path(path), 'port'
    if len(owners) > 1:
        return None, None, 'ambiguous-port'
    return None, None, 'reject'


def _upstream_path(path):
    if path.startswith('/v1/'):
        return path[3:]
    if path == '/v1':
        return '/'
    return path


def parse_simple_yaml(text):
    """Subset used by config/agents.yaml.example: maps, lists, flow collections, scalars."""
    lines = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        if '\t' in raw[:len(raw) - len(raw.lstrip(' \t'))]:
            raise ValueError('agents YAML 不接受制表符缩进')
        indent = len(raw) - len(raw.lstrip(' '))
        lines.append((indent, raw.strip()))
    value, index = _parse_block(lines, 0, 0)
    if index != len(lines):
        raise ValueError('agents YAML 未能完整解析')
    return value


def _parse_block(lines, index, indent):
    if index >= len(lines):
        return {}, index
    if lines[index][0] != indent:
        return {}, index
    if lines[index][1].startswith('- '):
        return _parse_list(lines, index, indent)
    return _parse_map(lines, index, indent)


def _parse_list(lines, index, indent):
    items = []
    while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith('- '):
        content = lines[index][1][2:].strip()
        index += 1
        if content.startswith('{') or content.startswith('['):
            items.append(_parse_flow(content))
            continue
        if content.endswith(':') or (':' in content and not content.startswith(('"', "'"))):
            key, rest = _split_kv(content)
            node = {}
            if rest == '':
                if index < len(lines) and lines[index][0] > indent:
                    node[key], index = _parse_block(lines, index, lines[index][0])
                else:
                    node[key] = None
            else:
                node[key] = _parse_flow(rest) if rest[:1] in '{[' else _scalar(rest)
            if index < len(lines) and lines[index][0] > indent:
                nested, index = _parse_block(lines, index, lines[index][0])
                if isinstance(nested, dict):
                    node.update(nested)
            items.append(node)
            continue
        items.append(_scalar(content) if content else None)
    return items, index


def _parse_map(lines, index, indent):
    mapping = {}
    while index < len(lines) and lines[index][0] == indent and not lines[index][1].startswith('- '):
        key, rest = _split_kv(lines[index][1])
        index += 1
        if rest == '':
            if index < len(lines) and lines[index][0] > indent:
                mapping[key], index = _parse_block(lines, index, lines[index][0])
            else:
                mapping[key] = None
        elif rest[:1] in '{[':
            mapping[key] = _parse_flow(rest)
        else:
            mapping[key] = _scalar(rest)
    return mapping, index


def _split_kv(text):
    if text.startswith('"') or text.startswith("'"):
        raise ValueError('不支持带引号的键')
    if ':' not in text:
        raise ValueError('缺少键值分隔符')
    key, rest = text.split(':', 1)
    return key.strip(), rest.strip()


def _scalar(text):
    if text in ('null', '~', ''):
        return None
    if text in ('true', 'True'):
        return True
    if text in ('false', 'False'):
        return False
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        return text[1:-1]
    if text.startswith('[') or text.startswith('{'):
        return _parse_flow(text)
    if re.fullmatch(r'-?\d+', text):
        return int(text)
    return text


def _parse_flow(text):
    value, index = _flow_value(text, 0)
    if index != len(text):
        raise ValueError('行内 YAML 未能完整解析: ' + text)
    return value


def _flow_value(text, index):
    index = _skip(text, index)
    if index >= len(text):
        return None, index
    char = text[index]
    if char == '[':
        return _flow_list(text, index + 1)
    if char == '{':
        return _flow_map(text, index + 1)
    if char in ('"', "'"):
        return _flow_quote(text, index)
    end = index
    while end < len(text) and text[end] not in ',}]':
        end += 1
    return _scalar(text[index:end].strip()), end


def _flow_list(text, index):
    items = []
    while True:
        index = _skip(text, index)
        if index < len(text) and text[index] == ']':
            return items, index + 1
        value, index = _flow_value(text, index)
        items.append(value)
        index = _skip(text, index)
        if index < len(text) and text[index] == ',':
            index += 1
            continue
        if index < len(text) and text[index] == ']':
            return items, index + 1
        raise ValueError('列表未闭合')


def _flow_map(text, index):
    mapping = {}
    while True:
        index = _skip(text, index)
        if index < len(text) and text[index] == '}':
            return mapping, index + 1
        if text[index] in ('"', "'"):
            key, index = _flow_quote(text, index)
        else:
            end = index
            while end < len(text) and text[end] not in ':}':
                end += 1
            key = text[index:end].strip()
            index = end
        index = _skip(text, index)
        if index >= len(text) or text[index] != ':':
            raise ValueError('映射缺少冒号')
        value, index = _flow_value(text, index + 1)
        mapping[key] = value
        index = _skip(text, index)
        if index < len(text) and text[index] == ',':
            index += 1
            continue
        if index < len(text) and text[index] == '}':
            return mapping, index + 1
        raise ValueError('映射未闭合')


def _flow_quote(text, index):
    quote = text[index]
    end = text.find(quote, index + 1)
    if end < 0:
        raise ValueError('引号未闭合')
    return text[index + 1:end], end + 1


def _skip(text, index):
    while index < len(text) and text[index] in ' \t':
        index += 1
    return index
