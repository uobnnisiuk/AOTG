"""Render the disabled Windows task definition without registering a task."""

from pathlib import PureWindowsPath
from subprocess import list2cmdline
from xml.etree.ElementTree import Element, SubElement, indent, tostring

TASK_NAME = "AOTG Local AutoDev"
_TASK_SCHEMA = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def disabled_task_xml(wsl_executable: str, workspace: str, *, distro: str):
    host_executable = PureWindowsPath(wsl_executable)
    if (not host_executable.is_absolute() or host_executable.drive.startswith("\\\\")
            or host_executable.name.casefold() != "wsl.exe" or ".." in host_executable.parts):
        raise ValueError("The Windows WSL executable must be pinned by absolute path")
    if (not isinstance(workspace, str) or not workspace.startswith("/")
            or any(not part or part in (".", "..") for part in workspace[1:].split("/"))
            or any(char in workspace for char in '\\\"\r\n\x00')):
        raise ValueError("The dedicated Linux checkout requires an absolute path")
    if (not distro or len(distro) > 80 or distro.startswith("-")
            or not all(c.isascii() and (c.isalnum() or c in "._-") for c in distro)):
        raise ValueError("Use the configured WSL distribution name")
    root = Element("Task", version="1.4", xmlns=_TASK_SCHEMA)
    SubElement(SubElement(root, "RegistrationInfo"), "Description").text = (
        "AOTG Local AutoDev read-only shadow preflight"
    )
    settings = SubElement(root, "Settings")
    for key, value in (
        ("MultipleInstancesPolicy", "IgnoreNew"), ("StartWhenAvailable", "false"),
        ("ExecutionTimeLimit", "PT40M"), ("Enabled", "false"),
    ):
        SubElement(settings, key).text = value
    execution = SubElement(SubElement(root, "Actions"), "Exec")
    SubElement(execution, "Command").text = str(host_executable)
    # This template is deliberately limited to preflight; it starts no implementation.
    SubElement(execution, "Arguments").text = list2cmdline([
        "--distribution", distro, "--cd", workspace,
        "--exec", "/usr/bin/python3", "-m", "aotg.autodev", "shadow",
    ])
    indent(root)
    return tostring(root, encoding="unicode", xml_declaration=True)
