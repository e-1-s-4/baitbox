"""Unit and integration tests for enhanced VirtualFilesystem features.

Covers chmod, chown, touch, append_file, truncate, symlinks, head, tail, wc,
checksum, diff, tree, disk_usage, path traversal safety, and thread safety.
"""

import threading
import unittest
from baitbox.vfs import VirtualFilesystem, MAX_FILE_SIZE


class EnhancedVFSTests(unittest.TestCase):
    def setUp(self):
        self.vfs = VirtualFilesystem()

    def test_default_file_hierarchy(self):
        """Verify standard Linux paths and decoy files exist."""
        self.assertTrue(self.vfs.exists("/etc/passwd"))
        self.assertTrue(self.vfs.exists("/etc/shadow"))
        self.assertTrue(self.vfs.exists("/etc/ssh/sshd_config"))
        self.assertTrue(self.vfs.exists("/etc/network/interfaces"))
        self.assertTrue(self.vfs.exists("/proc/cpuinfo"))
        self.assertTrue(self.vfs.exists("/proc/uptime"))
        self.assertTrue(self.vfs.exists("/dev/null"))
        self.assertTrue(self.vfs.exists("/bin/bash"))
        self.assertTrue(self.vfs.exists("/root/.bash_history"))

    def test_chmod_numeric_and_octal(self):
        """Test chmod with octal integer and numeric string."""
        self.vfs.write_file("/tmp/script.sh", b"#!/bin/bash\necho hello\n")
        # Change to 0777
        res = self.vfs.chmod("/tmp/script.sh", 0o777)
        self.assertTrue(res)
        stat = self.vfs.stat("/tmp/script.sh")
        self.assertEqual(stat["mode"], "-rwxrwxrwx")
        self.assertEqual(stat["mode_octal"], "0o777")

        # Change via string "600"
        res2 = self.vfs.chmod("/tmp/script.sh", "600")
        self.assertTrue(res2)
        stat2 = self.vfs.stat("/tmp/script.sh")
        self.assertEqual(stat2["mode"], "-rw-------")

        # Non-existent path returns False
        self.assertFalse(self.vfs.chmod("/tmp/nonexistent", 0o755))

    def test_chmod_symbolic(self):
        """Test chmod with symbolic permissions (+x, -w, u+x, etc.)."""
        self.vfs.write_file("/tmp/file.txt", b"content\n")
        self.vfs.chmod("/tmp/file.txt", 0o644)  # -rw-r--r--

        # Add execute permission
        self.vfs.chmod("/tmp/file.txt", "+x")
        stat = self.vfs.stat("/tmp/file.txt")
        self.assertIn("x", stat["mode"])

        # Remove write permission
        self.vfs.chmod("/tmp/file.txt", "-w")
        stat = self.vfs.stat("/tmp/file.txt")
        self.assertNotIn("w", stat["mode"])

    def test_chown(self):
        """Test chown for user and group (string and numeric)."""
        self.vfs.write_file("/tmp/app.py", b"print('test')\n")
        self.assertTrue(self.vfs.chown("/tmp/app.py", "ubuntu", "ubuntu"))
        stat = self.vfs.stat("/tmp/app.py")
        self.assertEqual(stat["owner"], "ubuntu")
        self.assertEqual(stat["group"], "ubuntu")
        self.assertEqual(stat["uid"], 1000)
        self.assertEqual(stat["gid"], 1000)

        # Non-existent path returns False
        self.assertFalse(self.vfs.chown("/tmp/not_real", "root"))

    def test_touch_and_append_file(self):
        """Test touch for creation and updating timestamp, and append_file."""
        # Touch new file
        self.assertTrue(self.vfs.touch("/tmp/newfile.log"))
        self.assertTrue(self.vfs.exists("/tmp/newfile.log"))
        self.assertEqual(self.vfs.read_file("/tmp/newfile.log"), b"")

        # Append to file
        self.assertTrue(self.vfs.append_file("/tmp/newfile.log", b"Line 1\n"))
        self.assertTrue(self.vfs.append_file("/tmp/newfile.log", b"Line 2\n"))
        self.assertEqual(self.vfs.read_file("/tmp/newfile.log"), b"Line 1\nLine 2\n")

        # Touch existing file updates timestamp
        old_mtime = self.vfs.stat("/tmp/newfile.log")["mtime"]
        self.assertTrue(self.vfs.touch("/tmp/newfile.log"))
        new_mtime = self.vfs.stat("/tmp/newfile.log")["mtime"]
        self.assertGreaterEqual(new_mtime, old_mtime)

    def test_truncate(self):
        """Test truncating a file."""
        self.vfs.write_file("/tmp/data.txt", b"ABCDEFGHIJ")
        self.assertTrue(self.vfs.truncate("/tmp/data.txt", 5))
        self.assertEqual(self.vfs.read_file("/tmp/data.txt"), b"ABCDE")

        # Extend with null bytes
        self.assertTrue(self.vfs.truncate("/tmp/data.txt", 8))
        self.assertEqual(self.vfs.read_file("/tmp/data.txt"), b"ABCDE\x00\x00\x00")

    def test_symlinks_and_resolution(self):
        """Test symlink creation, readlink, is_symlink, and resolve_path."""
        self.vfs.write_file("/tmp/target.txt", b"target payload\n")
        self.assertTrue(self.vfs.symlink("/tmp/target.txt", "/tmp/link.txt"))
        self.assertTrue(self.vfs.is_symlink("/tmp/link.txt"))
        self.assertEqual(self.vfs.readlink("/tmp/link.txt"), "/tmp/target.txt")

        # Resolving link should give target path
        resolved = self.vfs.resolve_path("/tmp/link.txt")
        self.assertEqual(resolved, "/tmp/target.txt")

        # Reading link path reads target content
        content = self.vfs.read_file("/tmp/link.txt")
        self.assertEqual(content, b"target payload\n")

        # Built-in symlink check: /usr/bin/python -> /usr/bin/python3
        self.assertTrue(self.vfs.is_symlink("/usr/bin/python"))
        self.assertEqual(self.vfs.resolve_path("/usr/bin/python"), "/usr/bin/python3")

    def test_head_and_tail(self):
        """Test head and tail line slicing."""
        lines = [f"Line {i}\n".encode() for i in range(1, 21)]
        self.vfs.write_file("/tmp/numbered.txt", b"".join(lines))

        # Default 10 lines
        h10 = self.vfs.head("/tmp/numbered.txt")
        self.assertEqual(len(h10), 10)
        self.assertEqual(h10[0], "Line 1")
        self.assertEqual(h10[-1], "Line 10")

        # Specific count
        h3 = self.vfs.head("/tmp/numbered.txt", lines=3)
        self.assertEqual(h3, ["Line 1", "Line 2", "Line 3"])

        # Tail 5 lines
        t5 = self.vfs.tail("/tmp/numbered.txt", lines=5)
        self.assertEqual(len(t5), 5)
        self.assertEqual(t5[0], "Line 16")
        self.assertEqual(t5[-1], "Line 20")

    def test_wc_and_checksum(self):
        """Test wc word/line counts and cryptographic checksums."""
        self.vfs.write_file("/tmp/sample.txt", b"hello world\nsecond line\nthird line\n")
        wc = self.vfs.wc("/tmp/sample.txt")
        self.assertEqual(wc["lines"], 3)
        self.assertEqual(wc["words"], 6)
        self.assertEqual(wc["bytes"], len(b"hello world\nsecond line\nthird line\n"))

        sha256 = self.vfs.checksum("/tmp/sample.txt", "sha256")
        self.assertIsNotNone(sha256)
        self.assertEqual(len(sha256), 64)

        md5 = self.vfs.checksum("/tmp/sample.txt", "md5")
        self.assertIsNotNone(md5)
        self.assertEqual(len(md5), 32)

    def test_diff(self):
        """Test unified diff between two files."""
        self.vfs.write_file("/tmp/f1.txt", b"A\nB\nC\n")
        self.vfs.write_file("/tmp/f2.txt", b"A\nB\nMODIFIED\n")
        diff = self.vfs.diff("/tmp/f1.txt", "/tmp/f2.txt")
        self.assertTrue(len(diff) > 0)
        diff_str = "".join(diff)
        self.assertIn("-C", diff_str)
        self.assertIn("+MODIFIED", diff_str)

    def test_disk_usage_and_tree(self):
        """Test disk usage reporting and directory tree visualization."""
        usage = self.vfs.disk_usage()
        self.assertIn("total", usage)
        self.assertIn("used", usage)
        self.assertIn("free", usage)
        self.assertGreater(usage["free"], 0)

        tree_str = self.vfs.tree("/etc", max_depth=2)
        self.assertIn("/etc", tree_str)
        self.assertIn("passwd", tree_str)

    def test_path_traversal_jail(self):
        """Test that paths attempting directory traversal are safely jailed."""
        resolved = self.vfs._normalize_path("/root", "../../../../etc/passwd")
        self.assertEqual(resolved, "/etc/passwd")

        resolved_root = self.vfs._normalize_path("/", "../../../..")
        self.assertEqual(resolved_root, "/")

    def test_thread_safety(self):
        """Test concurrent multi-threaded operations on VFS without exceptions."""
        errors = []

        def worker(worker_id: int):
            try:
                for i in range(50):
                    path = f"/tmp/worker_{worker_id}_{i}.txt"
                    self.vfs.write_file(path, f"data {i}".encode())
                    _ = self.vfs.read_file(path)
                    self.vfs.append_file(path, b" extra")
                    _ = self.vfs.stat(path)
                    self.vfs.rm(path)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors encountered: {errors}")


if __name__ == "__main__":
    unittest.main()
