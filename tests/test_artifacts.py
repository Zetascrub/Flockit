import os
import tempfile
import unittest

from utils.artifacts import ArtifactStore


class ArtifactStoreTests(unittest.TestCase):
    def test_save_text_writes_file_and_returns_relative_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore(tmpdir)
            artifact = store.save_text("192.168.1.10", "banner_22.txt", "SSH-2.0-OpenSSH", label="Banner 22", kind="banner")

            self.assertIsNotNone(artifact)
            self.assertEqual(artifact.label, "Banner 22")
            self.assertEqual(artifact.kind, "banner")
            self.assertEqual(artifact.path, "Scan-Data/192.168.1.10/banner_22.txt")

            full_path = os.path.join(tmpdir, "Scan-Data", "192.168.1.10", "banner_22.txt")
            with open(full_path) as f:
                self.assertEqual(f.read(), "SSH-2.0-OpenSSH")

    def test_save_json_serializes_dict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore(tmpdir)
            artifact = store.save_json("host1", "plugin_output.json", {"status": "ok"}, label="Plugin Output")

            full_path = os.path.join(tmpdir, "Scan-Data", "host1", "plugin_output.json")
            with open(full_path) as f:
                content = f.read()

            self.assertIn('"status"', content)
            self.assertIn('"ok"', content)
            self.assertEqual(artifact.path, "Scan-Data/host1/plugin_output.json")

    def test_save_project_file_writes_at_project_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ArtifactStore(tmpdir)
            full_path = store.save_project_file("report.md", "# Report\n")

            self.assertEqual(full_path, os.path.join(os.path.abspath(tmpdir), "report.md"))
            with open(full_path) as f:
                self.assertEqual(f.read(), "# Report\n")


if __name__ == "__main__":
    unittest.main()
