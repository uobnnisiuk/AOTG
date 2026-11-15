"""Capture freshly issued credentials on the owner's local terminal."""

import argparse
import getpass
import os
import re
import stat
import sys
import warnings
from pathlib import Path
from tempfile import NamedTemporaryFile

_GH_TOKEN = re.compile(r"github_pat_[A-Za-z0-9_]{20,500}")
_LINEAR_TOKEN = re.compile(r"lin_api_[A-Za-z0-9_-]{12,500}")
_GH_SETTINGS = (
    "https://github.com/settings/personal-access-tokens/new"
    "?name=AOTG%20UOB-58&target_name=uobnnisiuk"
    "&contents=write&pull_requests=write&issues=read"
)
_LINEAR_SETTINGS = "https://linear.app/settings/account/security"


class _PrivateArguments(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "認証登録のオプションを確認してください。\n")


def _private(path):
    info = path.lstat()
    if (
        path.resolve(strict=True) != path or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("AOTG private storage could not be verified")


def _github_hosts(token):
    if not _GH_TOKEN.fullmatch(token):
        raise ValueError("Use a newly issued fine-grained GitHub token")
    # The fine-grained token alphabet cannot introduce YAML syntax.
    return (
        "github.com:\n"
        "    user: uobnnisiuk\n"
        "    git_protocol: https\n"
        f"    oauth_token: {token}\n"
        "    users:\n"
        "        uobnnisiuk:\n"
        f"            oauth_token: {token}\n"
    ).encode("ascii")


def _linear_value(token):
    if not _LINEAR_TOKEN.fullmatch(token):
        raise ValueError("Use a newly issued team-scoped Linear key")
    return (token + "\n").encode("ascii")


def _save(path, content):
    """Publish this new private file atomically without replacing existing auth."""
    _private(path.parent)
    temporary = None
    try:
        with NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        if temporary is not None:
            temporary.unlink()
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _prompt(service, path, encode):
    if os.path.lexists(path):
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
        ):
            raise ValueError("Existing credential file is not private")
        print(f"{service} の保存済みファイルを保持しました。接続は別途確認します。")
        return True
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        value = getpass.getpass(f"{service} の新しい認証値をここに貼り付けて Enter（表示されません）: ")
    if not value:
        print(f"{service} は今回スキップしました。")
        return False
    _save(path, encode(value))
    print(f"{service} の認証値をAOTG専用領域に保存しました。")
    return True


def _local_terminal():
    if sys.platform != "linux" or not all(stream.isatty() for stream in (
        sys.stdin, sys.stdout, sys.stderr,
    )):
        return False
    try:
        descriptor = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        try:
            return os.tcgetpgrp(descriptor) == os.getpgrp()
        finally:
            os.close(descriptor)
    except OSError:
        return False


def main(argv=None):
    parser = _PrivateArguments(description="AOTG専用のローカル認証登録")
    parser.add_argument("service", choices=("github", "linear", "both"), default="both", nargs="?")
    args = parser.parse_args(argv)
    if not _local_terminal():
        print("K8のローカル端末で実行してください。", file=sys.stderr)
        return 1
    try:
        script = Path(__file__).absolute()
        if script.parent.name != "bin" or script.resolve(strict=True) != script:
            raise ValueError("Use the pinned AOTG installer")
        root = script.parent.parent
        config = root / "config"
        for path in (root, script.parent, config, config / "github"):
            _private(path)
        info = script.lstat()
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
        ):
            raise ValueError("Use the pinned AOTG installer")
        ready = []
        if args.service in ("github", "both"):
            print("GitHubの所有者で、Only select repositories の AOTG だけを選択してください。")
            print("権限は Contents と Pull requests の Read and write、Issues の Read を確認してください。")
            print(_GH_SETTINGS)
            ready.append(_prompt("GitHub", config / "github" / "hosts.yml", _github_hosts))
        if args.service in ("linear", "both"):
            print("Linearの結果欄を投稿したアカウントで、UOB チームのみ、Read と Write を選択してください。")
            print(_LINEAR_SETTINGS)
            ready.append(_prompt("Linear", config / "linear-authorization", _linear_value))
        return 0 if all(ready) else 1
    except (OSError, ValueError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        print("認証登録を停止しました。入力した値は表示しません。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
