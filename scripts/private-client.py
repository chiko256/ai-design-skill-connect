#!/usr/bin/env python3
"""Authenticate, verify and install the AI Design client. No design runtime is bundled."""
import argparse
from contextlib import contextmanager
import getpass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
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
TRANSACTION = '.private-client-transaction.json'
TOKEN_FORMAT = re.compile(r'wdp_[A-Za-z0-9_-]{43}')


@contextmanager
def process_lock(file):
    """OS-owned lock: a stopped process cannot leave a permanent busy flag."""
    file = Path(file)
    if file.is_symlink():
        raise ValueError('Unsafe lock path')
    fd = os.open(file, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    locked = False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (os.name != 'nt' and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
            raise ValueError('Unsafe lock permissions')
        if os.name == 'nt':
            import msvcrt
            if not info.st_size:
                os.write(fd, b'\0')
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise ValueError('Another update or migration is still running') from None
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Another update or migration is still running') from None
        locked = True
        yield
    finally:
        if locked:
            if os.name == 'nt':
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        # Keep the inode: unlinking an advisory lock can split concurrent owners.


def atomic_private(file, data):
    fd, name = tempfile.mkstemp(prefix='.client-write-', dir=file.parent)
    stage = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(stage, file)
    finally:
        if stage.exists():
            stage.unlink()


def client_version(fallback='2026.09.18.1'):
    """Use installed software identity, rather than a frozen connection setting."""
    root = Path(__file__).resolve().parents[1]
    receipt = root / RECEIPT
    try:
        version = json.loads(receipt.read_text(encoding='utf-8'))['version'] if receipt.is_file() else (root / 'VERSION').read_text().strip()
        if re.fullmatch(r'\d{4}\.\d{2}\.\d{2}\.\d+', version):
            return version
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return fallback


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def windows_credential(value=None, target='ai-design-skill.web-design-pro'):
    """Read/write this user's local Windows Credential Manager entry."""
    import ctypes
    from ctypes import wintypes

    class Credential(ctypes.Structure):
        _fields_ = [('Flags', wintypes.DWORD), ('Type', wintypes.DWORD),
                    ('TargetName', wintypes.LPWSTR), ('Comment', wintypes.LPWSTR),
                    ('LastWritten', wintypes.FILETIME), ('CredentialBlobSize', wintypes.DWORD),
                    ('CredentialBlob', ctypes.POINTER(ctypes.c_ubyte)), ('Persist', wintypes.DWORD),
                    ('AttributeCount', wintypes.DWORD), ('Attributes', ctypes.c_void_p),
                    ('TargetAlias', wintypes.LPWSTR), ('UserName', wintypes.LPWSTR)]

    api = ctypes.WinDLL('Advapi32.dll', use_last_error=True)
    pointer = ctypes.POINTER(Credential)
    api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(pointer)]
    api.CredReadW.restype = wintypes.BOOL
    api.CredWriteW.argtypes = [pointer, wintypes.DWORD]
    api.CredWriteW.restype = wintypes.BOOL
    api.CredFree.argtypes = [ctypes.c_void_p]
    api.CredFree.restype = None
    if value is not None:
        data = value.encode('utf-8')
        blob = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        record = Credential(Type=1, TargetName=target, CredentialBlobSize=len(data),
                            CredentialBlob=blob, Persist=2, UserName=getpass.getuser())
        if not api.CredWriteW(ctypes.byref(record), 0):
            raise OSError('Windows credential save failed')
    record = pointer()
    if not api.CredReadW(target, 1, 0, ctypes.byref(record)):
        if ctypes.get_last_error() == 1168:
            return ''
        raise OSError('Windows credential read failed')
    try:
        return ctypes.string_at(record.contents.CredentialBlob, record.contents.CredentialBlobSize).decode('utf-8')
    finally:
        api.CredFree(record)


def safe_name(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise ValueError('Invalid release path')
    path = PurePosixPath(name)
    if path.is_absolute() or str(path) != name or any(p in ('.', '..', '.git', '.runtime', RECEIPT, TRANSACTION) for p in path.parts):
        raise ValueError('Invalid release path')
    return path


def legacy_macos_token():
    """Read a user's existing 0600 token file without sourcing a shell or changing it."""
    token_file = Path.home() / '.config/web-design-pro/token'
    try:
        for parent in (token_file.parent.parent, token_file.parent):
            if parent.is_symlink():
                return ''
        fd = os.open(token_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 256:
                return ''
            value = stream.read(257).decode('ascii').strip()
        return value if re.fullmatch(r'wdp_[A-Za-z0-9_-]{43}', value) else ''
    except (OSError, UnicodeError):
        return ''


def credential(variable):
    value = os.environ.get(variable, '')
    if value and variable == 'WEB_DESIGN_PRO_TOKEN' and not TOKEN_FORMAT.fullmatch(value):
        raise ValueError('Invalid configured contract credential')
    if not value and sys.platform == 'win32' and variable == 'WEB_DESIGN_PRO_TOKEN':
        value = windows_credential()
    if not value and sys.platform == 'darwin' and variable == 'WEB_DESIGN_PRO_TOKEN':
        for command in [
            ['/bin/launchctl', 'getenv', variable],
            ['/usr/bin/security', 'find-generic-password', '-a', getpass.getuser(), '-s', 'ai-design-skill.web-design-pro', '-w']
        ]:
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode == 0 and TOKEN_FORMAT.fullmatch(result.stdout.strip()):
                value = result.stdout.strip()
                break
        if not value:
            value = legacy_macos_token()
    if value and variable == 'WEB_DESIGN_PRO_TOKEN' and not TOKEN_FORMAT.fullmatch(value):
        raise ValueError('Invalid configured contract credential')
    return value


def mcp_connection(config, endpoint=None, prompt=False):
    server = {}
    if config.is_file():
        server = tomllib.loads(config.read_text(encoding='utf-8')).get('mcp_servers', {}).get('web-design-pro', {})
    stdio_env = server.get('env', {}) if server.get('command') else {}
    url = endpoint or server.get('url') or stdio_env.get('WDP_MCP_URL') or os.environ.get('WDP_MCP_URL', DEFAULT_ENDPOINT)
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
    headers = {k: v for k, v in headers.items() if k.lower() != 'x-client-version'} | {
        'X-Client-Version': client_version(stdio_env.get('WDP_CLIENT_VERSION') or os.environ.get('WDP_CLIENT_VERSION', '2026.09.18.1'))}
    return url, headers


def connection(config, endpoint=None, prompt=False):
    url, headers = mcp_connection(config, endpoint, prompt)
    parsed = urllib.parse.urlsplit(url)
    base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, '', '', ''))
    return base, headers


def stdio_mcp(config):
    """Connector for this service's stateless JSON HTTP transport."""
    url, headers = mcp_connection(config)
    headers.update({'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'})
    opener = urllib.request.build_opener(NoRedirect())
    for line in sys.stdin.buffer:
        message = None
        try:
            if len(line) > 100 * 1024:
                raise ValueError('MCP request is too large')
            message = json.loads(line)
            if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
                raise ValueError('Invalid MCP message')
            headers['X-Client-Version'] = client_version(headers['X-Client-Version'])
            request = urllib.request.Request(url, data=line, headers=headers, method='POST')
            with opener.open(request, timeout=120) as response:
                raw = response.read(24 * 1024 * 1024 + 1)
            if 'id' not in message or 'method' not in message:
                continue
            if len(raw) > 24 * 1024 * 1024:
                raise ValueError('MCP response is too large')
            result = json.loads(raw)
            if not isinstance(result, dict) or result.get('id') != message['id']:
                raise ValueError('Invalid MCP response')
            if message.get('method') == 'initialize' and 'result' in result:
                headers['MCP-Protocol-Version'] = result['result']['protocolVersion']
        except (ValueError, KeyError, OSError, urllib.error.URLError):
            if not isinstance(message, dict) or 'id' not in message or 'method' not in message:
                continue
            result = {'jsonrpc': '2.0', 'id': message['id'], 'error': {'code': -32603, 'message': 'AI Design connection failed; check contract authentication and network'}}
        sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n')
        sys.stdout.buffer.flush()


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
    if not isinstance(value, dict) or value.get('schema') != 1 or not re.fullmatch(r'\d{4}\.\d{2}\.\d{2}\.\d+', value.get('version', '')):
        raise ValueError('Invalid client release')
    if value.get('archivePath') != '/client/archive' or not re.fullmatch(r'[a-f0-9]{64}', value.get('archiveSha256', '')):
        raise ValueError('Invalid client archive identity')
    files = value.get('files')
    if not isinstance(files, dict) or not 1 <= len(files) <= 500 or 'SKILL.md' not in files or 'scripts/private-client.py' not in files:
        raise ValueError('Invalid client file manifest')
    for name, record in files.items():
        safe_name(name)
        if not isinstance(record, dict) or not re.fullmatch(r'[a-f0-9]{64}', record.get('sha256', '')) or type(record.get('bytes')) is not int or not 0 <= record['bytes'] <= 8 * 1024 * 1024:
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


def recover_transaction(root):
    journal = root / TRANSACTION
    if not journal.exists():
        return
    if journal.is_symlink() or journal.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Unsafe recovery journal')
    state = json.loads(journal.read_text(encoding='utf-8'))
    new = validate_manifest(state['release'])
    old = validate_manifest(state['previous']) if state['previous'] else None
    old_files = old['files'] if old else {}
    changed = sorted(set(old_files) | set(new['files']))
    if state.get('schema') != 1 or state['changed'] != changed or not re.fullmatch(r'[a-f0-9]{32}', state['backupId']):
        raise ValueError('Invalid recovery journal')
    backups = root.parent / ('.' + root.name + '-private-backups') / state['backupId']
    existing = state['existing']
    if not isinstance(existing, dict) or not set(existing).issubset(changed) or backups.is_symlink() or backups.parent.is_symlink():
        raise ValueError('Unsafe recovery backup')
    for original in existing.values():
        if not isinstance(original, dict) or not re.fullmatch(r'[a-f0-9]{64}', original.get('sha256', '')) or type(original.get('mode')) is not int or not 0 <= original['mode'] <= 0o7777:
            raise ValueError('Invalid recovery preimage')
    receipt = root / RECEIPT
    if receipt.is_symlink():
        raise ValueError('Unsafe recovery receipt')
    current = json.loads(receipt.read_text(encoding='utf-8')) if receipt.is_file() else None
    if current not in (old, new):
        raise ValueError('Recovery receipt changed; preserve local edits')
    complete = True
    observed = {}
    for name in changed:
        target = target_path(root, name)
        if target.exists() and not target.is_file():
            raise ValueError('Recovery target changed; preserve local edits')
        actual = digest(target.read_bytes()) if target.exists() else None
        observed[name] = actual
        original = existing.get(name)
        if original:
            saved = target_path(backups, name)
            if not saved.is_file() or digest(saved.read_bytes()) != original['sha256']:
                raise ValueError('Recovery backup differs')
            if name in old_files and original['sha256'] not in {old_files[name]['sha256'], new['files'].get(name, {}).get('sha256')}:
                raise ValueError('Recovery original differs')
        desired = new['files'].get(name, {}).get('sha256')
        allowed = {desired, original['sha256'] if original else None}
        if name not in new['files']:
            allowed.add(None)
        elif original and desired:
            allowed.discard(None)
        if actual not in allowed:
            raise ValueError('Recovery found local edits; files were preserved')
        complete = complete and actual == desired
    if current == new:
        if not complete:
            raise ValueError('Committed update changed; files were preserved')
        journal.unlink()
        return True
    for name in reversed(changed):
        target = target_path(root, name)
        if (digest(target.read_bytes()) if target.is_file() else None) != observed[name]:
            raise ValueError('Client changed during recovery; local edits were preserved')
        if name in existing:
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_private(target, target_path(backups, name).read_bytes())
            target.chmod(existing[name]['mode'])
        elif target.is_file():
            target.unlink()
    journal.unlink()
    return True


def install(root, release, files, migrate=False):
    root = Path(root).absolute()
    if root.is_symlink():
        raise ValueError('Client destination is a symbolic link')
    root.parent.mkdir(parents=True, exist_ok=True)
    with process_lock(root.parent / ('.' + root.name + '-private-update.lock')):
        recovered = recover_transaction(root)
        return install_locked(root, release, files, migrate or recovered)


def install_locked(root, release, files, migrate):
    receipt = root / RECEIPT
    if receipt.is_symlink():
        raise ValueError('Client receipt is a symbolic link')
    previous = validate_manifest(json.loads(receipt.read_text())) if receipt.is_file() else None
    if root.exists() and any(root.iterdir()) and not previous and not migrate:
        raise ValueError('Initial migration requires --migrate; existing files were preserved')
    old_files = previous['files'] if previous else {}
    for name, record in old_files.items():
        target = target_path(root, name)
        # A legacy interrupted installer may have already written known release bytes.
        accepted = {record['sha256'], release['files'].get(name, {}).get('sha256')}
        if (not target.is_file() and not (not target.exists() and name not in release['files'])) or (target.is_file() and digest(target.read_bytes()) not in accepted):
            raise ValueError('Local client changes were found; back them up before updating: ' + name)
    if previous:
        for name in release['files'].keys() - old_files.keys():
            target = target_path(root, name)
            if target.exists() and (not target.is_file() or digest(target.read_bytes()) != release['files'][name]['sha256']):
                raise ValueError('A new release path conflicts with a local file; files were preserved: ' + name)
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
    if backups.parent.is_symlink():
        raise ValueError('Unsafe client backup directory')
    backups.mkdir(parents=True, mode=0o700)
    changed = sorted(set(old_files) | set(files))
    existing = {}
    for name in changed:
        target = target_path(root, name)
        if target.is_file():
            saved = backups / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            atomic_private(saved, target.read_bytes())
            existing[name] = {'sha256': digest(saved.read_bytes()), 'mode': stat.S_IMODE(target.stat().st_mode)}
            allowed = {old_files.get(name, {}).get('sha256'), release['files'].get(name, {}).get('sha256')}
            if not previous:
                allowed.update(release.get('legacyFiles', {}).get(name, []))
            if existing[name]['sha256'] not in allowed and (previous or digest(saved.read_bytes().replace(b'\r\n', b'\n')) not in allowed):
                raise ValueError('Client changed during backup; files were preserved')
    root.mkdir(mode=0o700, exist_ok=True)
    # atomic_private flushed each preimage before publishing the journal.
    journal = root / TRANSACTION
    atomic_private(journal, (json.dumps({'schema': 1, 'previous': previous, 'release': release,
                                      'changed': changed, 'existing': existing, 'backupId': backups.name}) + '\n').encode())
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
                actual = digest(target.read_bytes()) if target.is_file() else None
                if actual != existing.get(name, {}).get('sha256'):
                    raise ValueError('Client changed during update; files were preserved')
                if name in files:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(stage / name, target)
                elif target.exists():
                    target.unlink()
            state = stage / 'receipt.json'
            state.write_text(json.dumps(release, ensure_ascii=False, indent=2) + '\n')
            state.chmod(0o600)
            os.replace(state, receipt)
        journal.unlink()
    except BaseException:
        recover_transaction(root)
        raise
    return 'updated'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--config', type=Path, default=Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')) / 'config.toml')
    parser.add_argument('--endpoint')
    parser.add_argument('--migrate', action='store_true')
    parser.add_argument('--prompt-token', action='store_true')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--setup-windows-auth', action='store_true')
    mode.add_argument('--mcp-stdio', action='store_true')
    args = parser.parse_args()
    if args.setup_windows_auth:
        if sys.platform != 'win32' or not sys.stdin.isatty():
            raise ValueError('Run Windows authentication setup in your own Windows terminal')
        token = getpass.getpass('Contract token (hidden): ').strip()
        if not TOKEN_FORMAT.fullmatch(token):
            raise ValueError('Invalid contract token format')
        if windows_credential(token) != token:
            raise ValueError('Windows credential verification failed')
        print('ai-design-auth:configured')
        return
    if args.mcp_stdio:
        stdio_mcp(args.config)
        return
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
