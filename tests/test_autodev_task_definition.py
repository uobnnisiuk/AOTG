"""Validate disabled task rendering without touching Windows Task Scheduler."""

from unittest import TestCase
from xml.etree.ElementTree import fromstring

from aotg.autodev.task_definition import disabled_task_xml

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


class TaskDefinitionTests(TestCase):
    def test_definition_is_disabled_and_shadow_only(self):
        tree = fromstring(disabled_task_xml(
            r"C:\\Windows\\System32\\wsl.exe", "/example/aotg checkout", distro="Ubuntu"
        ))
        self.assertEqual(tree.findtext("t:Settings/t:Enabled", namespaces=NS), "false")
        self.assertEqual(tree.findtext("t:Settings/t:StartWhenAvailable", namespaces=NS), "false")
        self.assertEqual(tree.findtext("t:Settings/t:ExecutionTimeLimit", namespaces=NS), "PT40M")
        self.assertEqual(tree.findtext("t:Settings/t:MultipleInstancesPolicy", namespaces=NS), "IgnoreNew")
        self.assertIsNone(tree.find("t:Triggers", namespaces=NS))
        args = tree.findtext("t:Actions/t:Exec/t:Arguments", namespaces=NS)
        self.assertIn('"/example/aotg checkout"', args)
        self.assertTrue(args.endswith("-m aotg.autodev shadow"))

    def test_rejects_relative_nonlocal_or_ambiguous_execution_inputs(self):
        for binary, path, distro in (
            ("wsl.exe", "/example", "Ubuntu"),
            (r"\\\\host\\public\\wsl.exe", "/example", "Ubuntu"),
            (r"C:\\Windows\\wsl.exe", "/example/../other", "Ubuntu"),
            (r"C:\\Windows\\wsl.exe", '/example"other', "Ubuntu"),
            (r"C:\\Windows\\wsl.exe", "/example", "--help"),
        ):
            with self.subTest(binary=binary, path=path, distro=distro):
                with self.assertRaises(ValueError):
                    disabled_task_xml(binary, path, distro=distro)
