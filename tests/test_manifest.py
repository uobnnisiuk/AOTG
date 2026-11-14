import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aotg.adapters import adapter_for
from aotg.manifest import ManifestError, load_manifest, validate_manifest

FIXTURES = Path(__file__).parent / "fixtures"


class ManifestTests(unittest.TestCase):
    def test_environment_fixtures_distinguish_uma_and_dedicated_vram(self):
        linux = load_manifest(FIXTURES / "linux-mock.json")
        windows = load_manifest(FIXTURES / "windows-mock.json")
        shared, dedicated = linux["hardware"]["gpus"]
        self.assertEqual(linux["provenance"], {"mode": "fixture", "profile": "linux-example"})
        self.assertEqual(linux["hardware"]["system_ram_bytes"], 48 * 1024**3)
        self.assertEqual(shared["uma_aperture_bytes"], 8 * 1024**3)
        self.assertIsNone(shared["dedicated_vram_bytes"])
        self.assertEqual(dedicated["dedicated_vram_bytes"], 12 * 1024**3)
        self.assertIsNone(dedicated["uma_aperture_bytes"])
        self.assertIsNone(windows["hardware"]["gpus"])
        self.assertEqual(windows["client"]["name"], "Example client")

    def test_rejects_unsafe_or_invalid_manifest(self):
        def wrong_uma(data):
            data["hardware"]["gpus"][0]["dedicated_vram_bytes"] = 8 * 1024**3

        def wrong_ram(data):
            data["hardware"]["system_ram_basis"] = None

        def protected_changes(data):
            data["protection"]["production_changes_allowed"] = True

        def internal_endpoint(data):
            data["api"]["address"] = "192.0.2.1"

        def private_path(data):
            data["client"]["name"] = "/private/client"

        def wrong_version(data):
            data["schema_version"] = True

        for mutate in (wrong_uma, wrong_ram, protected_changes, internal_endpoint, private_path,
                       wrong_version):
            with self.subTest(mutate=mutate.__name__):
                data = load_manifest(FIXTURES / "linux-mock.json")
                mutate(data)
                with self.assertRaises(ManifestError):
                    validate_manifest(data)

    def test_rejects_json_with_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "manifest.json"
            file.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "duplicate"):
                load_manifest(file)


class DetectionTests(unittest.TestCase):
    @patch("aotg.adapters.LinuxAdapter._rocm_version", return_value="1.2.3")
    @patch("aotg.adapters.os.readlink", return_value="../../drivers/amdgpu")
    @patch("aotg.adapters.sys.platform", "linux")
    def test_linux_detects_family_and_memory_without_exposing_devices(self, *_):
        # Real Linux paths use slashes. The fake also runs under Windows CI.
        contents = {
            "/proc/cpuinfo": "model name : Example Linux CPU w/ Integrated Graphics\n"
                             "serial : hidden",
            "/proc/meminfo": "MemTotal: 47000000 kB",
            "/proc/sys/kernel/osrelease": "6.8.0-1-generic",
            "/etc/os-release": 'ID=ubuntu\nVERSION_ID="24.04"',
            "/sys/class/drm/card12/device/vendor": "0x1002",
            "/sys/class/drm/card12/device/device": "0x1586",
            "/sys/class/drm/card12/device/mem_info_vram_total": str(8 * 1024**3),
            "/sys/class/drm/card34/device/vendor": "0x1002",
            "/sys/class/drm/card34/device/device": "0x7551",
            "/sys/class/drm/card34/device/mem_info_vram_total": str(12 * 1024**3),
            "/sys/block/nvme0n1/size": "500000000",
        }
        lists = {
            "/sys/class/drm": [Path("/sys/class/drm/card12"), Path("/sys/class/drm/card34"),
                               Path("/sys/class/drm/card12-HDMI-A-1")],
            "/sys/block": [Path("/sys/block/nvme0n1"), Path("/sys/block/loop0")],
        }

        def read(path, limit=8192):
            return contents.get(path.as_posix(), "")[:limit]

        def entries(path):
            return lists.get(path.as_posix())

        with patch("aotg.adapters._read_text", side_effect=read):
            with patch("aotg.adapters._entries", side_effect=entries):
                manifest = adapter_for("linux").detect()

        self.assertEqual(manifest["provenance"]["mode"], "local-read-only")
        self.assertEqual(manifest["os"]["version"], "24.04")
        hardware = manifest["hardware"]
        self.assertEqual(hardware["cpu"], "Example Linux CPU with Integrated Graphics")
        self.assertEqual(hardware["system_ram_basis"], "os_usable")
        self.assertEqual(hardware["system_ram_bytes"], 47000000 * 1024)
        self.assertEqual(hardware["gpu_runtime"]["name"], "ROCm")
        self.assertEqual(hardware["storage"], [{"kind": "nvme", "capacity_bytes": 256_000_000_000}])
        shared, dedicated = hardware["gpus"]
        self.assertEqual(shared["architecture"], "gfx1151")
        self.assertEqual(shared["uma_aperture_bytes"], 8 * 1024**3)
        self.assertEqual(dedicated["architecture"], "gfx1201")
        self.assertEqual(dedicated["dedicated_vram_bytes"], 12 * 1024**3)
        self.assertIsNone(manifest["model"]["artifact_sha256"])
        text = json.dumps(manifest)
        for private_value in ("hidden", "card12", "nvme0n1"):
            self.assertNotIn(private_value, text)

    @patch("aotg.adapters.sys.getwindowsversion", return_value=(10, 0, 26100), create=True)
    @patch("aotg.adapters.sys.platform", "win32")
    def test_windows_uses_projected_inventory(self, *_):
        inventory = {
            "cpu": [{"Name": "Example Windows CPU w/ Integrated Graphics",
                     "NameNotRequested": "private"}],
            "ram": [{"Capacity": 12 * 1024**3}, {"Capacity": str(12 * 1024**3)}],
            "gpu": [{"Name": "AMD Radeon AI PRO R9700", "DriverVersion": "1.2.3",
                     "AdapterRAM": 5000}],
            "disk": None,
        }
        with patch("aotg.adapters._windows_inventory", return_value=inventory):
            manifest = adapter_for("windows").detect()

        self.assertEqual(manifest["os"]["kernel"], "10.0.26100")
        hardware = manifest["hardware"]
        self.assertEqual(hardware["cpu"], "Example Windows CPU with Integrated Graphics")
        self.assertEqual(hardware["system_ram_bytes"], 24 * 1024**3)
        self.assertEqual(hardware["system_ram_basis"], "installed")
        self.assertEqual(hardware["gpus"][0]["architecture"], "gfx1201")
        self.assertIsNone(hardware["gpus"][0]["dedicated_vram_bytes"])
        self.assertIsNone(hardware["storage"])
        self.assertIsNone(manifest["client"]["version"])
        self.assertNotIn("private", json.dumps(manifest))

    @patch("aotg.adapters.sys.platform", "win32")
    def test_cpu_label_does_not_accept_paths(self):
        inventory = {"cpu": [{"Name": "AMD Ryzen w/ /private/cpu"}]}
        with patch("aotg.adapters._windows_inventory", return_value=inventory):
            self.assertIsNone(adapter_for("windows").detect()["hardware"]["cpu"])

    @patch("aotg.adapters.sys.platform", "win32")
    def test_wrong_os_is_rejected(self):
        with self.assertRaises(ManifestError):
            adapter_for("linux").detect()
        with self.assertRaises(ManifestError):
            adapter_for("other")


if __name__ == "__main__":
    unittest.main()
