#!/usr/bin/env python3
"""Authenticate, verify and install the AI Design client. No design runtime is bundled."""
import argparse
import getpass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

DEFAULT_ENDPOINT = 'https://web-design-pro-mcp-production.up.railway.app/mcp'
RECEIPT = '.private-client-release.json'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise ValueError('Invalid release path')
    path = PurePosixPath(name)
    if path.is_absolute() or str(path) != name or any(p in ('.', '..', '.git', '.runtime', RECEIPT) for p in path.parts):
        raise ValueError('Invalid release path')
    return path


def credential(variable):
    value = os.environ.get(variable, '')
    if not value and sys.platform == 'darwin' and variable == 'WEB_DESIGN_PRO_TOKEN':
        for command in [
            ['/bin/launchctl', 'getenv', variable],
            ['/usr/bin/security', 'find-generic-password', '-a', getpass.getuser(), '-s', 'ai-design-skill.web-design-pro', '-w']
        ]:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                value = result.stdout.strip()
                break
    return value


def connection(config, endpoint=None, prompt=False):
    server = {}
    if config.is_file():
        server = tomllib.loads(config.read_text(encoding='utf-8')).get('mcp_servers', {}).get('web-design-pro', {})
    url = endpoint or server.get('url', DEFAULT_ENDPOINT)
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError('Invalid MCP endpoint')
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')):
        raise ValueError('Use HTTPS for the MCP endpoint')
    headers = dict(server.get('http_headers', {}))
    for name, variable in server.get('env_http_headers', {}).items():
        headers[name] = credential(variable)
    if server.get('bearer_token_env_var'):
        headers['Authorization'] = 'Bearer ' + credential(server['bearer_token_env_var'])
    if not any(k.lower() == 'authorization' and v.strip() not in ('', 'Bearer') for k, v in headers.items()):
        token = credential('WEB_DESIGN_PRO_TOKEN')
        if not token and prompt and sys.stdin.isatty():
            token = getpass.getpass('契約者トークン（入力内容は表示されません）: ')
        if not token:
            raise ValueError('Contract token is missing; keep the existing MCP authentication setup or enter it in your terminal')
        headers['Authorization'] = 'Bearer ' + token
    if not any(k.lower() == 'x-client-version' for k in headers):
        headers['X-Client-Version'] = '2026.09.18.1'
    base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, '', '', ''))
    return base, headers


def download(base, path, headers, limit):
    if path not in ('/client/manifest', '/client/archive'):
        raise ValueError('Invalid distribution endpoint')
    request = urllib.request.Request(base + path, headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=45) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        raise ValueError('Client distribution request rejected (HTTP ' + str(error.code) + ')') from None
    except urllib.error.URLError:
        raise ValueError('Client distribution is unavailable; existing files were preserved') from None
    if len(data) > limit:
        raise ValueError('Client distribution response exceeds its limit')
    return data


def validate_manifest(value):
    if value.get('schema') != 1 or not re.fullmatch(r'\d{4}\.\d{2}\.\d{2}\.\d+', value.get('version', '')):
        raise ValueError('Invalid client release')
    if value.get('archivePath') != '/client/archive' or not re.fullmatch(r'[a-f0-9]{64}', value.get('archiveSha256', '')):
        raise ValueError('Invalid client archive identity')
    files = value.get('files')
    if not isinstance(files, dict) or not 1 <= len(files) <= 500 or 'SKILL.md' not in files or 'scripts/private-client.py' not in files:
        raise ValueError('Invalid client file manifest')
    for name, record in files.items():
        safe_name(name)
        if not re.fullmatch(r'[a-f0-9]{64}', record.get('sha256', '')) or type(record.get('bytes')) is not int or not 0 <= record['bytes'] <= 8 * 1024 * 1024:
            raise ValueError('Invalid client file identity')
    if sum(v['bytes'] for v in files.values()) > 32 * 1024 * 1024:
        raise ValueError('Client release is too large')
    return value


def unpack(data, release):
    if len(data) != release.get('archiveBytes') or digest(data) != release['archiveSha256']:
        raise ValueError('Client archive checksum differs from its authenticated manifest')
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            name = str(safe_name(member.filename))
            if name in files or member.is_dir() or stat.S_ISLNK(member.external_attr >> 16) or name not in release['files']:
                raise ValueError('Unexpected client archive entry')
            record = release['files'][name]
            if member.file_size != record['bytes']:
                raise ValueError('Client file size mismatch')
            content = archive.read(member)
            if digest(content) != record['sha256']:
                raise ValueError('Client file checksum mismatch')
            files[name] = content
    if files.keys() != release['files'].keys():
        raise ValueError('Client archive file set differs from its manifest')
    return files


def target_path(root, name):
    result = root.joinpath(*safe_name(name).parts)
    for candidate in [root, *result.parents]:
        if candidate.is_symlink():
            raise ValueError('A client path contains a symbolic link; existing files were preserved')
        if candidate == root:
            break
    # Check descendants separately, including the file itself.
    current = root
    for part in safe_name(name).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('A client path contains a symbolic link; existing files were preserved')
    return result


def install(root, release, files, migrate=False):
    if root.is_symlink():
        raise ValueError('Client destination is a symbolic link')
    receipt = root / RECEIPT
    previous = validate_manifest(json.loads(receipt.read_text())) if receipt.is_file() else None
    if root.exists() and any(root.iterdir()) and not previous and not migrate:
        raise ValueError('Initial migration requires --migrate; existing files were preserved')
    old_files = previous['files'] if previous else {}
    for name, record in old_files.items():
        target = target_path(root, name)
        if not target.is_file() or digest(target.read_bytes()) != record['sha256']:
            raise ValueError('Local client changes were found; back them up before updating: ' + name)
    if not previous:
        for name in release['files']:
            target = target_path(root, name)
            if target.exists():
                allowed = release.get('legacyFiles', {}).get(name, [])
                value = target.read_bytes()
                if digest(value) not in allowed and digest(value.replace(b'\r\n', b'\n')) not in allowed:
                    raise ValueError('Unrecognized local client changes were preserved: ' + name)
    if previous and previous['version'] == release['version'] and previous['files'] == release['files']:
        return 'current'
    root.parent.mkdir(parents=True, exist_ok=True)
    backups = root.parent / ('.' + root.name + '-private-backups') / uuid.uuid4().hex
    backups.mkdir(parents=True, mode=0o700)
    changed = sorted(set(old_files) | set(files))
    existing = set()
    for name in changed:
        target = target_path(root, name)
        if target.is_file():
            saved = backups / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, saved)
            existing.add(name)
    root.mkdir(mode=0o700, exist_ok=True)
    applied = []
    try:
        with tempfile.TemporaryDirectory(prefix='.client-staging-', dir=root.parent) as directory:
            stage = Path(directory)
            for name, content in files.items():
                dest = stage / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
                dest.chmod(0o700 if release['files'][name].get('executable') else 0o600)
            for name in changed:
                target = target_path(root, name)
                applied.append(name)
                if name in files:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(stage / name, target)
                elif target.exists():
                    target.unlink()
            state = stage / 'receipt.json'
            state.write_text(json.dumps(release, ensure_ascii=False, indent=2) + '\n')
            state.chmod(0o600)
            os.replace(state, receipt)
    except BaseException:
        for name in reversed(applied):
            target = target_path(root, name)
            if name in existing:
                shutil.copy2(backups / name, target)
            elif target.is_file():
                target.unlink()
        raise
    return 'updated'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--config', type=Path, default=Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')) / 'config.toml')
    parser.add_argument('--endpoint')
    parser.add_argument('--migrate', action='store_true')
    parser.add_argument('--prompt-token', action='store_true')
    args = parser.parse_args()
    if args.destination.is_symlink():
        raise ValueError('Client destination is a symbolic link')
    base, headers = connection(args.config, args.endpoint, args.prompt_token)
    release = validate_manifest(json.loads(download(base, '/client/manifest', headers, 1024 * 1024)))
    files = unpack(download(base, release['archivePath'], headers, 8 * 1024 * 1024), release)
    result = install(args.destination.absolute(), release, files, args.migrate)
    print('ai-design-update:' + result)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, zipfile.BadZipFile, KeyError, TypeError, json.JSONDecodeError):
        # Do not echo HTTP responses, config values, credentials or tracebacks.
        print('ai-design-update:failed:authentication-network-or-local-change; existing files were preserved', file=sys.stderr)
        sys.exit(14)
