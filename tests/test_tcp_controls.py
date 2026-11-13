import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MANAGER = ROOT / 'modules/system/manage.sh'
V4 = 'net.ipv4.icmp_echo_ignore_all'
V6 = 'net.ipv6.icmp.echo_ignore_all'
MARKER = '# managed by opsbox.sh - ICMP echo replies\n'


def run(code, data='', env=None):
    return subprocess.run(
        ['bash', '--noprofile', '--norc', '-c',
         f'source {shlex.quote(str(MANAGER))}; has_tty() {{ return 1; }}; ' + code],
        input=data, text=True, capture_output=True, timeout=10,
        env={**os.environ, 'TERM': 'dumb', **(env or {})},
    )


class TcpControlsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.state = self.folder / 'state.json'
        self.config = self.folder / 'icmp.conf'
        self.env = {
            'TEST_ROOT': str(self.folder), 'SYSCTL_STATE': str(self.state),
            'PATH': str(self.folder) + os.pathsep + os.environ['PATH'],
        }
        self.state.write_text(json.dumps({V4: '0', V6: '0'}))
        stub = self.folder / 'sysctl'
        stub.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
path = pathlib.Path(os.environ['SYSCTL_STATE'])
state = json.loads(path.read_text())
args = sys.argv[1:]
def assign(raw, from_file=False):
    key, value = [x.strip() for x in raw.split('=', 1)]
    if from_file and key == os.environ.get('SYSCTL_FAIL_KEY'):
        sys.exit(1)
    if from_file and key == os.environ.get('SYSCTL_MISMATCH_KEY'):
        return
    state[key] = value
    path.write_text(json.dumps(state))
if args[0] == '-n':
    if args[1] not in state:
        sys.exit(1)
    print(state[args[1]])
elif args[0] == '-w':
    assign(args[1])
elif args[0] == '-p':
    for line in pathlib.Path(args[1]).read_text().splitlines():
        if line.strip() and not line.startswith('#'):
            assign(line, from_file=True)
else:
    sys.exit(1)
''')
        stub.chmod(0o755)

    def icmp(self, code, extra=None):
        return run('ICMP_SYSCTL_FILE="$TEST_ROOT/icmp.conf"; ' + code,
                   env={**self.env, **(extra or {})})

    def test_icmp_block_and_open_persist_only_echo_settings(self):
        for value in (1, 0):
            result = self.icmp(f'icmp_set_echo {value}')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(self.state.read_text()), {V4: str(value), V6: str(value)})
            self.assertEqual(self.config.read_text(), MARKER + f'{V4} = {value}\n{V6} = {value}\n')
        self.assertEqual(list(self.folder.glob('.opsbox-icmp.*')), [])

    def test_icmp_partial_failure_restores_values_and_existing_config(self):
        original = MARKER + f'{V4} = 0\n{V6} = 0\n'
        self.config.write_text(original)
        result = self.icmp('icmp_set_echo 1', {'SYSCTL_FAIL_KEY': V6})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_text(), original)
        self.assertEqual(json.loads(self.state.read_text()), {V4: '0', V6: '0'})

    def test_icmp_verification_failure_removes_new_config(self):
        result = self.icmp('icmp_set_echo 1', {'SYSCTL_MISMATCH_KEY': V6})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.config.exists())
        self.assertEqual(json.loads(self.state.read_text()), {V4: '0', V6: '0'})

    def test_icmp_unavailable_ipv6_is_not_reported_as_open(self):
        self.state.write_text(json.dumps({V4: '0'}))
        result = self.icmp('icmp_set_echo 1; icmp_status_text')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(V6, self.config.read_text())
        self.assertIn('IPv6 内核开关不可用', result.stdout)

    def test_icmp_rejects_unowned_files_symlinks_and_invalid_input(self):
        self.config.write_text('unrelated configuration\n')
        result = self.icmp('icmp_set_echo 1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_text(), 'unrelated configuration\n')
        self.config.unlink()
        self.config.symlink_to(self.state)
        self.assertNotEqual(self.icmp('icmp_set_echo 1').returncode, 0)
        self.assertNotEqual(self.icmp('icmp_set_echo 3').returncode, 0)
        self.assertEqual(json.loads(self.state.read_text()), {V4: '0', V6: '0'})

    def test_window_sizing_respects_bdp_minimum_maximum_and_memory(self):
        for args, expected in [
            ('1000 150 4096', 37500000),
            ('1 1 4096', 16777216),
            ('1000000 60000 4096', 536870912),
            ('1000 150 10', 10 * 1048576 * 30 // 100),
            ('01000 0150 04096', 37500000),
        ]:
            result = run('tcp_window_buffer_bytes ' + args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(int(result.stdout), expected)
        for args in ('0 150 4096', '1000 0 4096', '1000001 1 4096', '1000 1 0', '1.5 10 4096'):
            self.assertNotEqual(run('tcp_window_buffer_bytes ' + args).returncode, 0)

    def fixed_apply(self, data='FIXED\n', extra=None):
        return run(
            'TUNE_SYSCTL_FILE="$TEST_ROOT/tcp.conf"; '
            'DMIT_TCP_DEFAULT_FILE="$TEST_ROOT/dmit.conf"; '
            'BACKUP_BASE="$TEST_ROOT/backup"; TCP_SYSCTL_BACKUP="$BACKUP_BASE/tcp.orig"; '
            'TCPFIT_SYSCTL_FILE="$TEST_ROOT/tcpfit.conf"; TCPFIT_QDISC_SERVICE="$TEST_ROOT/tcpfit.service"; '
            'tcp_fixed_preflight() { return 0; }; bbr_check() { :; }; '
            'default_iface() { :; }; sysctl_apply_all() { :; }; '
            'tcp_fixed_apply 37500000', data,
            env={**self.env, **(extra or {})},
        )

    def test_custom_window_is_saved_and_verified_and_old_settings_are_backed_up(self):
        initial = {
            'net.core.rmem_max': '212992', 'net.core.wmem_max': '212992',
            'net.ipv4.tcp_rmem': '4096 87380 212992',
            'net.ipv4.tcp_wmem': '4096 65536 212992',
        }
        self.state.write_text(json.dumps(initial))
        result = self.fixed_apply()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('通过逐项运行值校验', result.stdout)
        config = (self.folder / 'tcp.conf').read_text()
        self.assertIn('net.ipv4.tcp_rmem = 4096 87380 37500000', config)
        self.assertEqual(json.loads(self.state.read_text())['net.core.rmem_max'], '37500000')
        self.assertIn('net.core.rmem_max=212992', (self.folder / 'backup/tcp.orig').read_text())
        again = self.fixed_apply(data='')
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertIn('无需重复应用', again.stdout)

    def test_custom_window_failed_apply_restores_config_and_runtime(self):
        initial = {'net.core.rmem_max': '212992', 'net.core.wmem_max': '212992',
                   'net.core.default_qdisc': 'fq_codel', 'net.ipv4.tcp_congestion_control': 'cubic',
                   'net.core.netdev_max_backlog': '1000', 'net.core.somaxconn': '4096',
                   'net.ipv4.tcp_max_syn_backlog': '4096'}
        self.state.write_text(json.dumps(initial))
        config = self.folder / 'tcp.conf'
        config.write_text('previous config\n')
        result = self.fixed_apply(extra={'SYSCTL_FAIL_KEY': 'net.core.wmem_max'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_text(), 'previous config\n')
        self.assertEqual(json.loads(self.state.read_text()), initial)

    def test_fixed_cancel_does_not_write_configuration(self):
        result = self.fixed_apply(data='no\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.folder / 'tcp.conf').exists())
        self.assertFalse((self.folder / 'backup').exists())

    def test_menu_routes_icmp_and_restore_and_nested_fixed_controls(self):
        result = run(
            'tcp_fixed_status_text() { :; }; tcpfit_status_summary() { :; }; icmp_status_text() { :; }; '
            'icmp_set_echo() { echo ICMP:$1; }; tcp_restore_default() { echo RESTORE; }; '
            'tcp_fixed_apply() { echo PRESET; }; tcp_window_tune() { echo WINDOW; }; tcp_menu',
            '5\n\n6\n\n7\n\n2\n1\n\n2\n\nb\nb\n',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for output in ('ICMP:1', 'ICMP:0', 'RESTORE', 'PRESET', 'WINDOW'):
            self.assertEqual(result.stdout.count(output), 1)
        for key, code in [('h', 20), ('q', 21), ('b', 0)]:
            result = run('tcp_fixed_menu', key + '\n')
            self.assertEqual(result.returncode, code)


if __name__ == '__main__':
    unittest.main()
