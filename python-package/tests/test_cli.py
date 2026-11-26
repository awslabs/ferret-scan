# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for release resolution, caching and checksums in ferret_scan.cli.

`ferret_scan.cli.requests` is replaced by a fake: no test touches the network.
"""

import hashlib
import types

import pytest

from ferret_scan import cli

TAG_URL = "https://api.github.com/repos/awslabs/ferret-scan/releases/tags/v{}"
LATEST_URL = "https://api.github.com/repos/awslabs/ferret-scan/releases/latest"
BINARY = b"\x7fELF fake binary"


class FakeHTTPError(Exception):
    def __init__(self, response=None):
        Exception.__init__(self, "http error")
        self.response = response


class FakeResponse:
    def __init__(self, status=200, json_data=None, content=b"", text=""):
        self.status_code = status
        self._json = json_data
        self.content = content
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise FakeHTTPError(self)

    def json(self):
        return self._json


class FakeRequests:
    """Stands in for the `requests` module: serves canned URLs, records every call."""

    exceptions = types.SimpleNamespace(
        Timeout=type("Timeout", (Exception,), {}),
        ConnectionError=type("ConnectionError", (Exception,), {}),
        HTTPError=FakeHTTPError,
        RequestException=Exception,
    )

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append(url)
        return self.routes.get(url, FakeResponse(404))


def release(version, checksum=None, with_checksums=True):
    name = "ferret-scan_%s_linux_amd64" % version
    digest = checksum or hashlib.sha256(BINARY).hexdigest()
    base = "https://dl.example/%s/" % version
    assets = [{"name": name, "browser_download_url": base + name}]
    routes = {base + name: FakeResponse(content=BINARY)}
    if with_checksums:
        assets.append({"name": "checksums.txt", "browser_download_url": base + "checksums.txt"})
        routes[base + "checksums.txt"] = FakeResponse(text="%s  %s\n" % (digest, name))
    return {"assets": assets}, routes


@pytest.fixture
def make_cli(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.FerretScanCLI, "get_platform_info", lambda self: ("linux", "amd64"))

    def build(version, routes):
        fake = FakeRequests(routes)
        monkeypatch.setattr(cli, "requests", fake)
        monkeypatch.setattr(cli, "get_installed_version", lambda: version)
        c = cli.FerretScanCLI()
        c.binary_dir = tmp_path
        return c, fake

    return build


def test_plain_version_resolves_the_tag_url(make_cli, capsys):
    data, routes = release("2.6.1")
    routes[TAG_URL.format("2.6.1")] = FakeResponse(json_data=data)
    c, fake = make_cli("2.6.1", routes)
    path = c.download_binary()
    assert fake.calls[0] == TAG_URL.format("2.6.1")
    assert LATEST_URL not in fake.calls
    assert path.read_bytes() == BINARY
    assert "Notice" not in capsys.readouterr().err


@pytest.mark.parametrize("version", ["0.0.0", "2.6.3.dev5", "2.6.2+local", "2.7.0rc1", None])
def test_non_plain_version_falls_back_to_latest_with_notice(make_cli, capsys, version):
    data, routes = release("2.6.2")
    routes[LATEST_URL] = FakeResponse(json_data=data)
    c, fake = make_cli(version, routes)
    c.download_binary()
    assert fake.calls[0] == LATEST_URL
    err = capsys.readouterr().err
    assert err.count("Notice:") == 1
    assert "latest GitHub release" in err


def test_missing_tag_is_an_error_naming_the_tag_with_no_fallback(make_cli):
    data, routes = release("2.6.2")
    routes[LATEST_URL] = FakeResponse(json_data=data)  # present, and must stay unused
    c, fake = make_cli("9.9.9", routes)
    with pytest.raises(RuntimeError) as exc:
        c.download_binary()
    assert "v9.9.9" in str(exc.value)
    assert cli.RELEASES_PAGE_URL in str(exc.value)
    assert fake.calls == [TAG_URL.format("9.9.9")]


def test_run_exits_nonzero_naming_the_tag_on_a_missing_tag(make_cli, capsys):
    c, _ = make_cli("9.9.9", {})
    assert c.run(["--version"]) == 2
    assert "v9.9.9" in capsys.readouterr().err


def test_cache_name_carries_the_version_and_platform(make_cli, tmp_path):
    c, _ = make_cli("2.6.1", {})
    assert c.get_binary_path() == tmp_path / "ferret-scan-2.6.1-linux-amd64"
    other, _ = make_cli("2.6.2", {})
    assert other.get_binary_path() != c.get_binary_path()


def test_windows_cache_name_keeps_exe(make_cli, monkeypatch):
    c, _ = make_cli("2.6.1", {})
    monkeypatch.setattr(cli.FerretScanCLI, "get_platform_info", lambda self: ("windows", "amd64"))
    assert c.get_binary_name() == "ferret-scan-2.6.1-windows-amd64.exe"


def test_legacy_unversioned_cache_is_ignored(make_cli, tmp_path):
    (tmp_path / "ferret-scan-linux-amd64").write_bytes(b"OLD BINARY FROM ANOTHER WHEEL")
    data, routes = release("2.6.1")
    routes[TAG_URL.format("2.6.1")] = FakeResponse(json_data=data)
    c, fake = make_cli("2.6.1", routes)
    path = c.download_binary()
    assert path.name == "ferret-scan-2.6.1-linux-amd64"
    assert path.read_bytes() == BINARY
    assert fake.calls  # it went to the network instead of reusing the legacy file


def test_versioned_cache_hit_makes_no_request(make_cli, tmp_path):
    (tmp_path / "ferret-scan-2.6.1-linux-amd64").write_bytes(BINARY)
    c, fake = make_cli("2.6.1", {})
    assert c.download_binary().read_bytes() == BINARY
    assert fake.calls == []


def test_checksum_is_fetched_from_the_same_release_and_verified(make_cli):
    data, routes = release("2.6.1")
    routes[TAG_URL.format("2.6.1")] = FakeResponse(json_data=data)
    c, fake = make_cli("2.6.1", routes)
    c.download_binary()
    assert "https://dl.example/2.6.1/checksums.txt" in fake.calls


def test_checksum_mismatch_refuses_the_binary(make_cli, tmp_path):
    data, routes = release("2.6.1", checksum="0" * 64)
    routes[TAG_URL.format("2.6.1")] = FakeResponse(json_data=data)
    c, _ = make_cli("2.6.1", routes)
    with pytest.raises(RuntimeError, match="Checksum mismatch"):
        c.download_binary()
    assert not (tmp_path / "ferret-scan-2.6.1-linux-amd64").exists()


def test_missing_checksums_manifest_refuses_the_binary(make_cli):
    data, routes = release("2.6.1", with_checksums=False)
    routes[TAG_URL.format("2.6.1")] = FakeResponse(json_data=data)
    c, _ = make_cli("2.6.1", routes)
    with pytest.raises(RuntimeError, match="checksums.txt"):
        c.download_binary()
