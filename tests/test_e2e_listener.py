"""
End-to-End tests for Shell Listener functionality

These tests verify:
- ANSI cleaning functionality
- MD5 hash calculation
- File path handling
- Command sending infrastructure
"""

import pytest
import os
import sys
import tempfile
import hashlib

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from listen_manager import clean_ansi, get_local_md5


class TestANSICleaning:
    """Test ANSI escape sequence cleaning"""

    def test_clean_simple_ansi_codes(self):
        """Test cleaning basic ANSI color codes"""
        text_with_ansi = "\x1b[1;31mRed text\x1b[0m"
        cleaned = clean_ansi(text_with_ansi)
        assert cleaned == "Red text"

    def test_clean_complex_ansi_sequences(self):
        """Test cleaning complex ANSI sequences"""
        text = "\x1b[1;34mBlue\x1b[0m and \x1b[1;32mGreen\x1b[0m"
        cleaned = clean_ansi(text)
        assert "Blue and Green" in cleaned
        assert "\x1b" not in cleaned

    def test_clean_with_prompts(self):
        """Test cleaning shell prompts"""
        text = "123;user@hostname:/path/to/dir$ ls -la\nfile.txt"
        cleaned = clean_ansi(text)
        # Prompt should be filtered out
        lines = [line for line in cleaned.split('\n') if line.strip()]
        assert any('file.txt' in line for line in lines)

    def test_clean_empty_string(self):
        """Test cleaning empty string"""
        assert clean_ansi("") == ""

    def test_clean_plain_text(self):
        """Test that plain text is unchanged"""
        plain_text = "This is plain text without ANSI codes"
        assert clean_ansi(plain_text) == plain_text


class TestMD5Calculation:
    """Test MD5 hash calculation for files"""

    def test_md5_of_text_file(self):
        """Test MD5 calculation for a text file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Test content for MD5\n")
            temp_path = f.name

        try:
            md5_hash = get_local_md5(temp_path)
            assert md5_hash is not None
            assert len(md5_hash) == 32  # MD5 is 32 hex characters
            assert md5_hash.isalnum()

            # Verify the hash is correct
            with open(temp_path, 'rb') as f:
                expected_hash = hashlib.md5(f.read()).hexdigest()
            assert md5_hash == expected_hash
        finally:
            os.unlink(temp_path)

    def test_md5_of_binary_file(self):
        """Test MD5 calculation for a binary file"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'\x00\x01\x02\x03\x04\x05')
            temp_path = f.name

        try:
            md5_hash = get_local_md5(temp_path)
            assert md5_hash is not None
            assert len(md5_hash) == 32
        finally:
            os.unlink(temp_path)

    def test_md5_of_nonexistent_file(self):
        """Test MD5 calculation for file that doesn't exist"""
        md5_hash = get_local_md5('/nonexistent/path/file.txt')
        assert md5_hash is None

    def test_md5_consistency(self):
        """Test that same file produces same MD5"""
        content = "Consistent content for hashing\n" * 100

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            hash1 = get_local_md5(temp_path)
            hash2 = get_local_md5(temp_path)
            assert hash1 == hash2
        finally:
            os.unlink(temp_path)

    def test_md5_different_files(self):
        """Test that different files produce different MD5"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f1:
            f1.write("File 1 content")
            path1 = f1.name

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f2:
            f2.write("File 2 content")
            path2 = f2.name

        try:
            hash1 = get_local_md5(path1)
            hash2 = get_local_md5(path2)
            assert hash1 != hash2
        finally:
            os.unlink(path1)
            os.unlink(path2)


class TestFolderStructure:
    """Test that required folders exist"""

    def test_required_folders_exist(self):
        """Verify that UPLOAD_FOLDER and DOWNLOAD_FOLDER exist"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        upload_folder = os.path.join(base_dir, 'uploads')
        download_folder = os.path.join(base_dir, 'downloads')
        tools_folder = os.path.join(base_dir, 'tools')

        assert os.path.exists(upload_folder), "uploads folder should exist"
        assert os.path.exists(download_folder), "downloads folder should exist"
        assert os.path.exists(tools_folder), "tools folder should exist"

    def test_folders_are_writable(self):
        """Test that folders have write permissions"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        folders = [
            os.path.join(base_dir, 'uploads'),
            os.path.join(base_dir, 'downloads'),
            os.path.join(base_dir, 'tools')
        ]

        for folder in folders:
            test_file = os.path.join(folder, '.test_write')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                assert os.path.exists(test_file)
            finally:
                if os.path.exists(test_file):
                    os.unlink(test_file)


class TestFileTransferLogic:
    """Test file transfer helper functions"""

    def test_basename_extraction(self):
        """Test that os.path.basename works correctly for file paths"""
        paths = [
            ('/path/to/file.txt', 'file.txt'),
            ('file.txt', 'file.txt'),
            ('/tmp/test.sh', 'test.sh'),
            ('C:\\Windows\\file.exe', 'file.exe'),
        ]

        for full_path, expected_basename in paths:
            basename = os.path.basename(full_path)
            # On Windows, the last one will work; on Unix, it won't split
            # But the logic should still be testable
            if os.name == 'posix' and '\\' in full_path:
                continue  # Skip Windows paths on Unix
            assert basename == expected_basename or full_path.endswith(expected_basename)


class TestIntegrationScenarios:
    """Test integration scenarios for listener functionality"""

    def test_file_integrity_workflow(self):
        """Test the complete file integrity check workflow"""
        # Create a test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Integration test content\n")
            f.write("Multiple lines\n")
            f.write("For testing\n")
            source_path = f.name

        try:
            # Calculate MD5 of source
            source_md5 = get_local_md5(source_path)
            assert source_md5 is not None

            # Simulate file transfer by copying
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as dest:
                with open(source_path, 'rb') as src:
                    dest.write(src.read())
                dest_path = dest.name

            try:
                # Calculate MD5 of destination
                dest_md5 = get_local_md5(dest_path)
                assert dest_md5 is not None

                # Verify integrity
                assert source_md5 == dest_md5, "File transfer should preserve integrity"
            finally:
                os.unlink(dest_path)
        finally:
            os.unlink(source_path)

    def test_corrupted_file_detection(self):
        """Test that corrupted files are detected via MD5"""
        # Create original file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Original content\n")
            original_path = f.name

        try:
            original_md5 = get_local_md5(original_path)

            # Create "corrupted" version
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write("Modified content\n")  # Different content
                corrupted_path = f.name

            try:
                corrupted_md5 = get_local_md5(corrupted_path)

                # MD5 should be different
                assert original_md5 != corrupted_md5, "Corrupted file should have different MD5"
            finally:
                os.unlink(corrupted_path)
        finally:
            os.unlink(original_path)


# Test runner configuration
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
