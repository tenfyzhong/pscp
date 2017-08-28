#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pexpect import spawn, TIMEOUT, EOF, ExceptionPexpect
import os


__all__ = ['pscp', 'ExceptionPscp']


class ExceptionPscp(ExceptionPexpect):
    """Raised for local exceptions
    """


class pscp(spawn):
    """This class extends pexpect.spawn to specialize setting up scp
    connections. There are only one method named :meth:`scp` to do the action.

    Example::

        import pscp
        import getpass
        s = pscp.pscp()
        src = raw_input('src: ')
        dst = raw_input('dst: ')
        hostname = raw_input('hostname: ')
        username = raw_input('username: ')
        password = getpass.getpass('password: ')
        try:
            s.to_server(src, dst, hostname, username, password)
        except:
            pass

    Example showing how to specify ssh options::

        import psftp
        s = psftp.psftp(options={
            "StrictHostKeyChecking": "no",
            "UserKnownHostsFile": "/dev/null"}
        )
        # ...

    Note that if you have ssh-agent running while doing development with psftp
    then this can lead to a lot of confusion. Many X display managers (xdm,
    gdm, kdm, etc.) will automatically start a GUI agent. You may see a GUI
    dialog box popup asking for a password during development. You should turn
    off any key agents during testing. The 'force_password' attribute will turn
    off public key authentication. This will only work if the remote SSH server
    is configured to allow password logins. Example of useing 'force_password'
    attribute::

        s = pscp.pscp()
        s.force_password = True
        # ...
    """

    def __init__(
            self,
            timeout=60,
            maxread=100,
            searchwindowsize=None,
            logfile=None,
            cwd=None,
            env=None,
            ignore_sighup=True,
            echo=True,
            options={},
            encoding=None,
            codec_errors='strict'):
        super(pscp, self).__init__(
            None,
            timeout=timeout,
            maxread=maxread,
            searchwindowsize=searchwindowsize,
            logfile=logfile,
            cwd=cwd,
            env=env,
            ignore_sighup=ignore_sighup,
            echo=echo,
            encoding=encoding,
            codec_errors=codec_errors)
        self.name = '<pscp>'

        self.SSH_OPTS = ("-o'RSAAuthentication=no'"
                         + " -o 'PubkeyAuthentication=no'")
        self.force_password = False

        # User defined SSH options, eg,
        # ssh.otions = dict(StrictHostKeyChecking="no",
        # UserKnownHostsFile="/dev/null")
        self.options = options

    def to_server(
            self,
            src,
            dst,
            server,
            username,
            password='',
            terminal_type='ansi',
            timeout=10,
            port=None,
            ssh_key=None,
            quiet=True,
            check_local_ip=True):
        """copy src to server
        """
        self = pscp(
            self.timeout,
            self.maxread,
            self.searchwindowsize,
            self.logfile,
            self.cwd,
            self.env,
            self.ignore_sighup,
            self.echo,
            self.options,
            self.encoding,
            self.codec_errors)
        return self._scp(
            src,
            dst,
            server,
            username,
            password,
            to_server=True,
            terminal_type=terminal_type,
            timeout=timeout,
            port=port,
            ssh_key=ssh_key,
            quiet=quiet,
            check_local_ip=check_local_ip)

    def from_server(
            self,
            src,
            dst,
            server,
            username,
            password='',
            terminal_type='ansi',
            timeout=10,
            port=None,
            ssh_key=None,
            quiet=True,
            check_local_ip=True):
        """copy src from server
        """
        self = pscp(
            self.timeout,
            self.maxread,
            self.searchwindowsize,
            self.logfile,
            self.cwd,
            self.env,
            self.ignore_sighup,
            self.echo,
            self.options,
            self.encoding,
            self.codec_errors)
        return self._scp(
            src,
            dst,
            server,
            username,
            password,
            to_server=False,
            terminal_type=terminal_type,
            timeout=timeout,
            port=port,
            ssh_key=ssh_key,
            quiet=quiet,
            check_local_ip=check_local_ip)

    def _scp(
            self,
            src,
            dst,
            server,
            username,
            password,
            to_server,
            terminal_type,
            timeout,
            port,
            ssh_key,
            quiet,
            check_local_ip):
        """ cp src to dst. If to_server is True, then copy from local to
        server, else copy from server to local, in other words,

        if to_server:
            scp src username@dst
        else:
            scp username@src dst

        """
        ssh_options = ''.join([" -o '%s=%s'" % (o, v) for
                               (o, v) in self.options.items()])
        if quiet:
            ssh_options += ' -q'
        if not check_local_ip:
            ssh_options += " -o'NoHostAuthenticationForLocalhost=yes'"
        if self.force_password:
            ssh_options += ' ' + self.SSH_OPTS
        if port is not None:
            ssh_options += ' -P %s' % (str(port))
        if ssh_key is not None and os.path.isfile(ssh_key):
            ssh_options = ssh_options + ' -i %s' % (ssh_key)

        cmd = 'scp %s %s@%s:%s' % (src, username, server, dst) \
            if to_server else 'scp %s@%s:%s %s' % (username, server, src, dst)
        super(pscp, self)._spawn(cmd)

        phase_expect = [
            "(?i)are you sure you want to continue connecting",
            "(?i)(?:password)|(?:passphrase for key)",
            "(?i)permission denied",
            "(?i)terminal type",
            TIMEOUT,
            "(?i)connection closed by remote host",
            "(?i)no such file or directory",
            EOF]

        expected = [False] * len(phase_expect)

        while True:
            i = self.expect(phase_expect, timeout=timeout)
            if i == 0:
                # New certificate -- always accept it.
                # This is what you get if SSH does not have the remote host's
                # public key stored in the 'known_hosts' cache.
                assert not expected[i]
                expected[i] = True
                self.sendline('yes')
            elif i == 1:  # password or passphrase
                if expected[i]:
                    self.close()
                    raise ExceptionPscp('password refused')
                expected[i] = True
                self.sendline(password)
            elif i == 2:
                # permission denied -- password was bad.
                self.close()
                raise ExceptionPscp('permission denied')
            elif i == 3:
                assert not expected[i]
                expected[i] = True
                self.sendline(terminal_type)
            elif i == 4:
                self.close()
                raise ExceptionPscp('timeout')
            elif i == 5:
                # Connection closed by remote host
                self.close()
                raise ExceptionPscp('connection closed')
            elif i == 6:
                self.close()
                raise ExceptionPscp('No such file or directory')
            elif i == 7:
                self.close()
                break

        return True
