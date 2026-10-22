#!/usr/bin/env python3
"""OpenAI-compatible observation gateway. Responses are forwarded unchanged.

Each agent is bound by path prefix `/a/<agentId>` or by its own listen port.
tool_call_id values already present in the protocol join rounds into a chain.
The gateway does not rewrite the model response or inject identifiers.
"""
import datetime
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def _imports():
    try:
        from runtime.agents_config import load_agents, peer_allowed, resolve_route
        from runtime.redact import redact_text, secret_findings
        from runtime.semantic_extract import ChainBook, content_text, extract_entities, triggering_untrusted, untrusted_segments
        return load_agents, peer_allowed, resolve_route, redact_text, secret_findings, ChainBook, content_text, extract_entities, triggering_untrusted, untrusted_segments
    except ImportError:
        sys.path.insert(0, os.environ.get('AGENTREINS_RUNTIME', '/opt/agentreins-runtime'))
        from agents_config import load_agents, peer_allowed, resolve_route
        from redact import redact_text, secret_findings
        from semantic_extract import ChainBook, content_text, extract_entities, triggering_untrusted, untrusted_segments
        return load_agents, peer_allowed, resolve_route, redact_text, secret_findings, ChainBook, content_text, extract_entities, triggering_untrusted, untrusted_segments

load_agents, peer_allowed, resolve_route, redact_text, secret_findings, ChainBook, content_text, extract_entities, triggering_untrusted, untrusted_segments = _imports()


def _summarize_payload(payload):
    try:
        from runtime.tool_definitions import summarize_payload
    except ImportError:
        sys.path.insert(0, os.environ.get('AGENTREINS_RUNTIME', '/opt/agentreins-runtime'))
        from tool_definitions import summarize_payload
    return summarize_payload(payload)

UPSTREAM = os.environ.get('AGENTREINS_UPSTREAM', 'https://api.openai.com/v1').rstrip('/')
OUT = os.environ.get('AGENTREINS_HOST_LOG', '/var/log/agentreins/host.jsonl')
SEMANTIC_OUT = os.environ.get('AGENTREINS_SEMANTIC_LOG', '/var/log/agentreins/semantic.jsonl')


def clean(value):
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if re.search(r'(?i)^(authorization|api[_-]?key|password|token|secret|cookie)$', str(k)) else clean(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value[:100]]
    if isinstance(value, str):
        return redact_text(value)
    return value


class Gateway:
    def __init__(self, upstream=UPSTREAM, out_paths=None, agents=None, chain=None):
        self.upstream = upstream.rstrip('/')
        self.out_paths = out_paths or [OUT, SEMANTIC_OUT]
        self.agents = agents or []
        self.chain = chain or ChainBook()
        self.lock = threading.Lock()

    def emit(self, op, request_id, data, peer, result='CAPTURED', evidence=None):
        evidence = dict(evidence or {})
        evidence.setdefault('requestId', request_id)
        evidence.setdefault('peer', peer)
        evidence.setdefault('upstream', self.upstream)
        evidence.setdefault('attribution', 'CLIENT_CONNECTION')
        event = {
            'time': datetime.datetime.now().astimezone().isoformat(),
            'component': 'SemanticGateway',
            'category': 'semantic',
            'operation': op,
            'process': 'model-gateway',
            'pid': os.getpid(),
            'ppid': os.getppid(),
            'containerId': '',
            'container': '',
            'resource': json.dumps(clean(data), ensure_ascii=False)[:12000],
            'result': result,
            'source': 'OpenAI-compatible application boundary',
            'evidence': evidence,
            'data': json.dumps({'requestId': request_id, 'peer': peer, 'agentId': evidence.get('agentId')}),
        }
        event['eventKey'] = hashlib.sha256((request_id + op + event['time'] + event['resource'][:2000]).encode()).hexdigest()
        line = json.dumps(event, ensure_ascii=False) + '\n'
        with self.lock:
            for path in self.out_paths:
                directory = os.path.dirname(path)
                if directory:
                    os.makedirs(directory, exist_ok=True)
                with open(path, 'a') as handle:
                    handle.write(line)
        return event

    def handle(self, request):
        rid = uuid.uuid4().hex
        peer = request.client_address[0]
        phase = 'request'
        started = time.monotonic()
        try:
            size = int(request.headers.get('Content-Length', '0'))
            if size > 32 * 1024 * 1024:
                request.send_error(413)
                return
            body = request.rfile.read(size) if size else b''
            payload = {}
            if body:
                try:
                    payload = json.loads(body)
                except ValueError:
                    payload = {}
            port = request.server.server_address[1]
            agent, upstream_path, how = self._route(request.path, port)
            if agent is None and self.agents:
                self.emit('MODEL_REJECTED', rid, {'path': request.path}, peer, 'REJECTED', {'confidence': 'unknown', 'routeBasis': '路由未绑定到已配置 agent'})
                request.send_error(404)
                return
            if agent is None and not self.agents:
                if not request.path.startswith('/v1/') or '..' in request.path:
                    request.send_error(404)
                    return
                upstream_path = request.path[3:]
                route_evidence = {'confidence': 'unknown', 'routeBasis': '未配置 agents，语义事件不参与 S02/S03'}
            else:
                if not peer_allowed(peer, agent['gateway']['peerAllowlist']):
                    self.emit('MODEL_REJECTED', rid, {'path': request.path}, peer, 'REJECTED', {'confidence': 'unknown', 'routeBasis': 'peer 不在 ' + agent['id'] + ' 的允许网段'})
                    request.send_error(403)
                    return
                route_evidence = {
                    'agentId': agent['id'],
                    'confidence': 'observed',
                    'routeBasis': '网关%s %s 绑定 %s，peer 在允许网段' % ('端口' if how == 'port' else '路径', agent['gateway']['port'] or agent['gateway']['pathPrefix'], agent['id']),
                }
            chain_state = {'chainId': rid, 'chainConfidence': 'observed', 'untrustedSegments': [], 'chainHasUntrusted': False, 'conflict': False}
            if isinstance(payload, dict) and payload.get('messages'):
                chain_state = self.chain.observe_request(rid, payload.get('messages'), (agent or {}).get('knowledgeMarkers'))
                if chain_state.get('conflict'):
                    route_evidence = dict(route_evidence)
                    route_evidence['chainConfidence'] = 'unknown'
                    route_evidence['confidence'] = 'unknown'
            evidence = {**route_evidence, 'requestId': rid, 'peer': peer, 'chainId': chain_state.get('chainId'), 'chainConfidence': chain_state.get('chainConfidence'), 'chainHasUntrusted': chain_state.get('chainHasUntrusted')}
            if isinstance(payload, dict) and (payload or agent is not None or not self.agents):
                if request.command == 'POST' and payload:
                    summary = self._request_summary(payload, chain_state)
                    self.emit('MODEL_REQUEST', rid, summary, peer, evidence={**evidence, 'untrustedSegments': chain_state.get('untrustedSegments') or [], 'textExcerpt': summary.get('textExcerpt', '')})
                    for message in payload.get('messages') or []:
                        if isinstance(message, dict) and message.get('role') == 'tool':
                            self.emit('TOOL_RESULT', rid, {'tool_call_id': message.get('tool_call_id'), 'excerpt': content_text(message.get('content'))[:512]}, peer, evidence=evidence)
            if request.command == 'POST' and isinstance(payload, dict) and agent is not None:
                self._emit_definitions(rid, peer, payload, evidence, agent)
            headers = {k: v for k, v in request.headers.items() if k.lower() not in ('host', 'connection', 'content-length', 'accept-encoding', 'transfer-encoding')}
            upstream = urllib.request.Request(self.upstream + upstream_path, data=body if request.command == 'POST' else None, headers=headers, method=request.command)
            phase = 'upstream_connect'
            try:
                response = urllib.request.urlopen(upstream, timeout=660)
            except urllib.error.HTTPError as error:
                response = error
            if 'text/event-stream' not in response.headers.get('Content-Type', ''):
                phase = 'upstream_read'
                raw_body = response.read()
                status = response.status
                ctype = response.headers.get('Content-Type', 'application/json')
                response.close()
                phase = 'downstream_write'
                self._write_unchanged(request, status, ctype, raw_body)
                if request.command == 'POST':
                    self._record_response(rid, peer, raw_body, status, evidence, chain_state)
                return
            self._stream(request, response, rid, peer, evidence, chain_state)
        except (BrokenPipeError, ConnectionResetError) as error:
            self.emit('MODEL_INTERRUPTED', rid, {'reason': 'connection interrupted', 'phase': phase, 'elapsed': round(time.monotonic() - started, 2), 'type': type(error).__name__}, peer, 'PARTIAL')
            request.close_connection = True
            if phase.startswith('upstream'):
                try:
                    request.send_error(502, 'Upstream connection interrupted')
                except OSError:
                    pass
        except Exception as error:
            self.emit('MODEL_ERROR', rid, {'type': type(error).__name__, 'phase': phase, 'elapsed': round(time.monotonic() - started, 2)}, peer, 'FAILED')
            try:
                request.send_error(502, 'Model gateway upstream failure')
            except OSError:
                pass

    def _route(self, path, port):
        if not self.agents:
            return None, None, 'unbound'
        return resolve_route(self.agents, path, port)

    def _emit_definitions(self, rid, peer, payload, evidence, agent):
        summary = _summarize_payload(payload)
        if summary is None:
            return None
        baseline = (agent or {}).get('toolDefinitionBaseline') or {}
        extra = dict(evidence)
        extra['toolDefinitions'] = summary['tools']
        extra['toolBaseline'] = {
            'learnRequests': int(baseline.get('learnRequests') or 10),
            'learnSeconds': int(baseline.get('learnSeconds') or 600),
            'pinned': dict(baseline.get('pinned') or {}),
        }
        return self.emit(
            'TOOL_DEFINITIONS', rid,
            {'toolCount': len(summary['tools']), 'names': [item['name'] for item in summary['tools']]},
            peer, evidence=extra,
        )

    def _request_summary(self, payload, chain_state):
        messages = payload.get('messages') or []
        roles = [m.get('role') for m in messages if isinstance(m, dict)]
        segments = chain_state.get('untrustedSegments') or []
        excerpt = ' '.join(segment.get('excerpt') or '' for segment in triggering_untrusted(segments))[:512]
        return {
            'path': '/v1/chat/completions',
            'model': payload.get('model'),
            'messageCount': len(messages),
            'roles': roles[:40],
            'untrustedCount': len(triggering_untrusted(segments)),
            'textExcerpt': excerpt,
            'truncated': True,
        }

    def _record_response(self, rid, peer, raw_body, status, evidence, chain_state):
        try:
            decoded = json.loads(raw_body)
        except ValueError:
            decoded = {'non_json_response': True, 'bytes': len(raw_body)}
        summary = self._response_summary(decoded)
        self.emit('MODEL_RESPONSE', rid, summary, peer, str(status), evidence=evidence)
        for choice in decoded.get('choices') or []:
            message = choice.get('message') or {}
            for tool in message.get('tool_calls') or []:
                self._emit_tool(rid, peer, tool, evidence, chain_state)
            reasoning = message.get('reasoning_content') or message.get('reasoning')
            if reasoning:
                self.emit('MODEL_REASONING', rid, {'reasoning': redact_text(str(reasoning))[:512]}, peer, evidence=evidence)

    def _emit_tool(self, rid, peer, tool, evidence, chain_state):
        if not isinstance(tool, dict):
            return
        function = tool.get('function') or {}
        name = function.get('name') or ''
        arguments = function.get('arguments') if function.get('arguments') is not None else ''
        raw_arguments = arguments if isinstance(arguments, str) else json.dumps(arguments, ensure_ascii=False)
        entities = extract_entities(name, raw_arguments)
        findings = secret_findings(raw_arguments)
        tool_id = tool.get('id') or ''
        chain_id = chain_state.get('chainId') or evidence.get('chainId')
        if tool_id and chain_state.get('chainConfidence') != 'unknown':
            self.chain.remember_tool(chain_id, tool_id)
        tool_evidence = dict(evidence)
        tool_evidence.update({
            'toolCallId': tool_id,
            'toolName': name,
            'argsDigest': entities.get('argsDigest'),
            'argsEntities': {k: entities.get(k) for k in ('urls', 'hosts', 'paths', 'commands')},
            'chainHasUntrusted': chain_state.get('chainHasUntrusted') or bool(triggering_untrusted(chain_state.get('untrustedSegments'))),
            'secretFindings': findings,
        })
        body = {'id': tool_id, 'type': tool.get('type') or 'function', 'function': {'name': name, 'arguments': redact_text(raw_arguments)[:4096]}}
        self.emit('TOOL_CALL', rid, body, peer, evidence=tool_evidence)

    def _response_summary(self, decoded):
        if not isinstance(decoded, dict):
            return {'non_json_response': True}
        choices = []
        for choice in (decoded.get('choices') or [])[:4]:
            message = (choice or {}).get('message') or {}
            choices.append({
                'index': choice.get('index'),
                'contentExcerpt': redact_text(content_text(message.get('content')))[:512],
                'toolCallIds': [tool.get('id') for tool in (message.get('tool_calls') or []) if isinstance(tool, dict)],
            })
        return {'choices': choices, 'usage': decoded.get('usage'), 'stream': decoded.get('stream', False), 'truncated': True}

    def _write_unchanged(self, request, status, ctype, raw_body):
        request.send_response(status)
        request.send_header('Content-Type', ctype)
        request.send_header('Content-Length', str(len(raw_body)))
        request.send_header('Connection', 'close')
        request.end_headers()
        request.close_connection = True
        request.wfile.write(raw_body)
        request.wfile.flush()

    def _stream(self, request, response, rid, peer, evidence, chain_state):
        request.send_response(response.status)
        request.send_header('Content-Type', response.headers.get('Content-Type', 'application/json'))
        request.send_header('Connection', 'close')
        request.end_headers()
        request.close_connection = True
        sse = 'text/event-stream' in response.headers.get('Content-Type', '')
        full = bytearray()
        choices = {}
        usage = None
        while True:
            chunk = response.readline() if sse else response.read(65536)
            if not chunk:
                break
            request.wfile.write(chunk)
            request.wfile.flush()
            if not sse:
                full.extend(chunk)
                continue
            if chunk.startswith(b'data:'):
                try:
                    part = json.loads(chunk[5:].strip())
                except ValueError:
                    continue
                if part.get('usage'):
                    usage = part['usage']
                for choice in part.get('choices') or []:
                    state = choices.setdefault(choice.get('index', 0), {'content': '', 'reasoning_content': '', 'tool_calls': {}})
                    delta = choice.get('delta') or choice.get('message') or {}
                    for field in ('content', 'reasoning_content', 'reasoning'):
                        if isinstance(delta.get(field), str):
                            state[field] = state.get(field, '') + delta[field]
                    for tool in delta.get('tool_calls') or []:
                        target = state['tool_calls'].setdefault(tool.get('index', 0), {'id': '', 'type': 'function', 'function': {'name': '', 'arguments': ''}})
                        if tool.get('id'):
                            target['id'] = tool['id']
                        for key in ('name', 'arguments'):
                            target['function'][key] += (tool.get('function') or {}).get(key, '') or ''
        response.close()
        if sse:
            decoded = {'choices': [{'index': index, 'message': {**value, 'tool_calls': list(value['tool_calls'].values())}} for index, value in choices.items()], 'usage': usage, 'stream': True}
        else:
            try:
                decoded = json.loads(full)
            except ValueError:
                decoded = {'non_json_response': True, 'bytes': len(full)}
        if request.command == 'POST':
            self._record_response(rid, peer, json.dumps(decoded).encode(), response.status, evidence, chain_state)


def make_handler(gateway):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            gateway.handle(self)

        def do_POST(self):
            gateway.handle(self)

        def log_message(self, *args):
            pass
    return Handler


def load_configured_agents():
    path = os.environ.get('AGENTREINS_AGENTS', '/etc/agentreins/agents.yaml')
    if path and os.path.isfile(path):
        return load_agents(path)
    return []


def serve(gateway=None):
    gateway = gateway or Gateway(agents=load_configured_agents())
    groups = {}
    if not gateway.agents:
        bind = os.environ.get('AGENTREINS_BIND', '127.0.0.1')
        port = int(os.environ.get('AGENTREINS_GATEWAY_PORT', '18900'))
        groups[(bind, port)] = True
    else:
        for agent in gateway.agents:
            bind = agent['gateway']['bind'] or os.environ.get('AGENTREINS_BIND', '127.0.0.1')
            port = agent['gateway']['port'] or int(os.environ.get('AGENTREINS_GATEWAY_PORT', '18900'))
            groups[(bind, port)] = True
    servers = [ThreadingHTTPServer(address, make_handler(gateway)) for address in groups]
    if len(servers) == 1:
        servers[0].serve_forever()
        return servers[0]
    for extra in servers[1:]:
        threading.Thread(target=extra.serve_forever, daemon=True).start()
    servers[0].serve_forever()
    return servers[0]


if __name__ == '__main__':
    serve()
