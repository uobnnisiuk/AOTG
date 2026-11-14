"""Read local platform metadata without invoking inference, clients, or network APIs."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Protocol

from .manifest import ManifestError, validate_manifest


class HardwareAdapter(Protocol):
    def detect(self) -> dict:
        """Return an anonymized environment manifest for the local platform."""


_AMD_DEVICES = {
    # These PCI IDs identify families shared by multiple retail models.
    ("0x1002", "0x1586"): ("AMD Strix Halo", "gfx1151", "shared"),
    ("0x1002", "0x7551"): ("AMD Navi 48 Radeon PRO", "gfx1201", "dedicated"),
}
_LABEL_PATTERN = r"[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,119}"
_BLOCK_DEVICE = re.compile(r"(?:nvme[0-9]+n[0-9]+|sd[a-z]+|hd[a-z]+|vd[a-z]+|mmcblk[0-9]+)")


def _local_manifest(adapter: str) -> dict:
    return {
        "schema_version": 1,
        "adapter": adapter,
        "provenance": {"mode": "local-read-only", "profile": None},
        "hardware": {
            "cpu": None,
            "system_ram_bytes": None,
            "system_ram_basis": None,
            "gpus": None,
            "gpu_runtime": {"name": None, "version": None},
            "storage": None,
        },
        "os": {"family": adapter, "distribution": None, "version": None, "kernel": None},
        "engine": {"name": None, "version": None, "sha256": None, "backend": None,
                   "speculation": None},
        "model": {"name": None, "quantization": None, "format": None, "artifact_sha256": None},
        "api": {"format": None, "transport": None, "authentication": None, "streaming": None,
                "tool_calls": None},
        "client": {"name": None, "version": None},
        "measurement": {
            "scenario": None,
            "context_tokens": None,
            "input_tokens": None,
            "output_limit_tokens": None,
            "batch_tokens": None,
            "micro_batch_tokens": None,
            "seed": None,
            "cache_state": None,
            "cooling_profile": None,
        },
        "protection": {
            "read_only": True,
            "production_changes_allowed": False,
            "secrets_collection_allowed": False,
            "network_probes_allowed": False,
        },
    }


def _label(value: object) -> str | None:
    if isinstance(value, str) and re.fullmatch(_LABEL_PATTERN, value.strip()):
        return value.strip()
    return None


def _read_text(path: Path, limit: int = 8192) -> str:
    try:
        with path.open("rb") as metadata:
            return metadata.read(limit).decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _entries(path: Path) -> list[Path] | None:
    try:
        return sorted(path.iterdir())
    except OSError:
        return None


def _positive(value: object) -> int | None:
    if type(value) is int and value > 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,20}", value):
        return int(value) or None
    return None


def _gpu(name: str | None, architecture: str | None, driver: str | None,
         driver_version: str | None, memory_kind: str | None, memory_bytes: int | None) -> dict:
    return {
        "name": name,
        "architecture": architecture,
        "driver": driver,
        "driver_version": driver_version,
        "memory_kind": memory_kind,
        "dedicated_vram_bytes": memory_bytes if memory_kind == "dedicated" else None,
        "uma_aperture_bytes": memory_bytes if memory_kind == "shared" else None,
    }


class LinuxAdapter:
    def detect(self) -> dict:
        if sys.platform != "linux":
            raise ManifestError("The Linux adapter requires a local Linux host.")
        manifest = _local_manifest("linux")
        manifest["os"].update(self._os_metadata())
        hardware = manifest["hardware"]
        cpu = re.search(r"^model name\s*:\s*([^\n]+)", _read_text(Path("/proc/cpuinfo")),
                        re.MULTILINE)
        if cpu:
            hardware["cpu"] = _label(cpu[1])
        memory = re.search(r"^MemTotal:\s*([0-9]{1,20})\s+kB",
                           _read_text(Path("/proc/meminfo")), re.MULTILINE)
        if memory and int(memory[1]) > 0:
            hardware["system_ram_bytes"] = int(memory[1]) * 1024
            hardware["system_ram_basis"] = "os_usable"
        hardware["gpus"] = self._gpus()
        hardware["storage"] = self._storage()
        rocm = self._rocm_version()
        if rocm:
            hardware["gpu_runtime"] = {"name": "ROCm", "version": rocm}
        validate_manifest(manifest)
        return manifest

    @staticmethod
    def _os_metadata() -> dict:
        release = _read_text(Path("/etc/os-release"))
        metadata = {"kernel": _label(_read_text(Path("/proc/sys/kernel/osrelease"), 128))}
        for key, field in (("ID", "distribution"), ("VERSION_ID", "version")):
            match = re.search(rf"^{key}=([^\n]+)", release, re.MULTILINE)
            if match:
                metadata[field] = _label(match[1].strip('"'))
        return metadata

    @staticmethod
    def _rocm_version() -> str | None:
        try:
            version_file = Path("/opt/rocm/.info/version").resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        if not version_file.is_relative_to("/opt") or not version_file.is_file():
            return None
        value = _read_text(version_file, 128)
        if re.fullmatch(r"[0-9][0-9A-Za-z.+_-]{0,79}", value):
            return value
        return None

    @staticmethod
    def _gpus() -> list[dict] | None:
        cards = _entries(Path("/sys/class/drm"))
        if cards is None:
            return None
        gpus = []
        for card in cards:
            if not re.fullmatch(r"card[0-9]+", card.name):
                continue
            device = card / "device"
            vendor = _read_text(device / "vendor", 32)
            device_id = _read_text(device / "device", 32)
            name, architecture, memory_kind = _AMD_DEVICES.get(
                (vendor, device_id), (None, None, None)
            )
            try:
                driver = _label(os.readlink(device / "driver").split("/")[-1])
            except OSError:
                driver = None
            memory = None
            if driver == "amdgpu" and memory_kind:
                memory = _positive(_read_text(device / "mem_info_vram_total", 32))
            driver_version = None
            if driver:
                driver_version = _label(_read_text(Path("/sys/module") / driver / "version", 128))
            gpus.append(_gpu(name, architecture, driver, driver_version, memory_kind, memory))
        return gpus

    @staticmethod
    def _storage() -> list[dict] | None:
        devices = _entries(Path("/sys/block"))
        if devices is None:
            return None
        storage = []
        for device in devices:
            if not _BLOCK_DEVICE.fullmatch(device.name):
                continue
            sectors = _positive(_read_text(device / "size", 32))
            rotational = _read_text(device / "queue" / "rotational", 16)
            kind = "nvme" if device.name.startswith("nvme") else {"0": "ssd", "1": "hdd"}.get(
                rotational
            )
            storage.append({"kind": kind, "capacity_bytes": sectors * 512 if sectors else None})
        return storage


# Query only public product/build and capacity fields. Exclude identities, network,
# service state, command lines, and PowerShell profiles.
_WINDOWS_QUERY = r"""
$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function ReadInventory ($Class, $Properties, $Namespace = 'root/cimv2') {
    try {
        @(Get-CimInstance -Namespace $Namespace -ClassName $Class -Property $Properties -OperationTimeoutSec 2 |
            Select-Object -Property $Properties)
    } catch {
        $null
    }
}
[ordered]@{
    cpu = @(ReadInventory Win32_Processor Name)
    ram = @(ReadInventory Win32_PhysicalMemory Capacity)
    gpu = @(ReadInventory Win32_VideoController @('Name', 'DriverVersion'))
    disk = @(ReadInventory MSFT_PhysicalDisk @('BusType', 'MediaType', 'Size') 'root/Microsoft/Windows/Storage')
} | ConvertTo-Json -Compress -Depth 4
"""


def _windows_inventory() -> dict:
    from ctypes import create_unicode_buffer, windll

    system_dir = create_unicode_buffer(32768)
    system_dir_length = windll.kernel32.GetSystemDirectoryW(system_dir, len(system_dir))
    if not 0 < system_dir_length < len(system_dir):
        return {}
    powershell = Path(system_dir.value) / "WindowsPowerShell/v1.0/powershell.exe"
    try:
        result = subprocess.run(
            [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
             _WINDOWS_QUERY],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=12,
            check=True,
        )
        inventory = json.loads(result.stdout.decode("utf-8"))
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    return inventory if isinstance(inventory, dict) else {}


def _rows(inventory: dict, key: str) -> list[dict] | None:
    rows = inventory.get(key)
    if isinstance(rows, list) and all(isinstance(row, dict) for row in rows):
        return rows
    return None


class WindowsAdapter:
    def detect(self) -> dict:
        if sys.platform != "win32":
            raise ManifestError("The Windows adapter requires a local Windows host.")
        manifest = _local_manifest("windows")
        build = ".".join(str(part) for part in sys.getwindowsversion()[:3])
        manifest["os"].update({"distribution": "Windows", "version": build, "kernel": build})
        inventory = _windows_inventory()
        hardware = manifest["hardware"]
        processors = _rows(inventory, "cpu")
        if processors:
            hardware["cpu"] = _label(processors[0].get("Name"))
        ram = _rows(inventory, "ram")
        if ram:
            capacities = [_positive(row.get("Capacity")) for row in ram]
            if all(capacities):
                hardware["system_ram_bytes"] = sum(capacities)
                hardware["system_ram_basis"] = "installed"
        controllers = _rows(inventory, "gpu")
        if controllers is not None:
            hardware["gpus"] = [self._gpu_metadata(row) for row in controllers]
        disks = _rows(inventory, "disk")
        if disks is not None:
            hardware["storage"] = [self._disk_metadata(row) for row in disks]
        validate_manifest(manifest)
        return manifest

    @staticmethod
    def _gpu_metadata(controller: dict) -> dict:
        name = _label(controller.get("Name"))
        architecture, memory_kind = None, None
        if name and re.search(r"\b8060S\b", name, re.IGNORECASE):
            architecture, memory_kind = "gfx1151", "shared"
        if name and re.search(r"\bR9700\b", name, re.IGNORECASE):
            architecture, memory_kind = "gfx1201", "dedicated"
        return _gpu(name, architecture, None, _label(controller.get("DriverVersion")),
                    memory_kind, None)

    @staticmethod
    def _disk_metadata(disk: dict) -> dict:
        kind = "nvme" if disk.get("BusType") == 17 else {3: "hdd", 4: "ssd"}.get(
            disk.get("MediaType")
        )
        return {"kind": kind, "capacity_bytes": _positive(disk.get("Size"))}


def adapter_for(name: str) -> HardwareAdapter:
    if name == "linux":
        return LinuxAdapter()
    if name == "windows":
        return WindowsAdapter()
    raise ManifestError("Unknown local hardware adapter.")
