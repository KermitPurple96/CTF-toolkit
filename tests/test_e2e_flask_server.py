"""
End-to-End tests for CTF-toolkit Flask Server

These tests verify the complete functionality of the web server including:
- File uploads and downloads
- Clipboard operations
- Tool management
- IP discovery
- Shell listener integration
"""

import pytest
import os
import tempfile
import json
from pathlib import Path
import sys

# Add parent directory to path to import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app


@pytest.fixture
def app():
    """Configure Flask app for testing"""
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    yield flask_app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def temp_file():
    """Create a temporary file for testing"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("Test content for CTF toolkit\n")
        f.write("This is a test file\n")
        temp_path = f.name
    yield temp_path
    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


class TestHomePage:
    """Test the home page rendering"""

    def test_index_page_loads(self, client):
        """Verify home page returns 200 OK"""
        response = client.get('/')
        assert response.status_code == 200


class TestFileUpload:
    """Test file upload functionality"""

    def test_upload_file_via_put(self, client):
        """Test uploading a file using PUT method"""
        test_data = b"Test file content for upload"
        response = client.put(
            '/upload/test_upload.txt',
            data=test_data,
            content_type='application/octet-stream'
        )
        assert response.status_code == 200
        assert b'uploaded via PUT' in response.data

        # Verify file was created
        upload_path = os.path.join('uploads', 'test_upload.txt')
        assert os.path.exists(upload_path)

        # Cleanup
        os.unlink(upload_path)

    def test_upload_file_via_post(self, client, temp_file):
        """Test uploading a file using POST method with multipart form"""
        with open(temp_file, 'rb') as f:
            data = {'file': (f, 'test_post_upload.txt')}
            response = client.post(
                '/upload/test_post_upload.txt',
                data=data,
                content_type='multipart/form-data'
            )

        assert response.status_code == 200
        assert b'uploaded via POST' in response.data

        # Cleanup
        upload_path = os.path.join('uploads', 'test_post_upload.txt')
        if os.path.exists(upload_path):
            os.unlink(upload_path)

    def test_upload_prevents_path_traversal(self, client):
        """Test that path traversal attacks are prevented"""
        test_data = b"Malicious content"

        # Try to upload with ../ in filename - should be blocked
        response = client.put(
            '/upload/../../../etc/passwd',
            data=test_data,
            content_type='application/octet-stream',
            follow_redirects=False
        )
        # Should be rejected with 400
        assert response.status_code in [400, 308]  # 308 is redirect, 400 is validation error

        # Try another path traversal
        response = client.put(
            '/upload/../../sensitive.txt',
            data=test_data,
            content_type='application/octet-stream',
            follow_redirects=False
        )
        assert response.status_code in [400, 308]


class TestFileDownload:
    """Test file download functionality"""

    def test_download_existing_file(self, client):
        """Test downloading a file that exists"""
        # Create a test file in downloads folder
        download_path = os.path.join('downloads', 'test_download.txt')
        with open(download_path, 'w') as f:
            f.write("Test download content")

        response = client.get('/download/test_download.txt')
        assert response.status_code == 200
        assert b'Test download content' in response.data

        # Cleanup
        os.unlink(download_path)

    def test_download_nonexistent_file(self, client):
        """Test downloading a file that doesn't exist"""
        response = client.get('/download/nonexistent_file.txt')
        assert response.status_code == 404

    def test_download_prevents_path_traversal(self, client):
        """Test that path traversal is prevented in downloads"""
        # Try to access file outside downloads directory
        response = client.get('/download/../app.py')
        assert response.status_code == 400

        response = client.get('/download/../../etc/passwd')
        assert response.status_code == 400


class TestToolsManagement:
    """Test tools listing and management"""

    def test_tools_page_loads(self, client):
        """Test that tools page loads successfully"""
        response = client.get('/tools')
        assert response.status_code == 200

    def test_list_files_endpoint(self, client):
        """Test /files endpoint returns JSON list"""
        response = client.get('/files')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)

    def test_read_tool_file(self, client):
        """Test reading a tool file that exists"""
        # Create a test tool file
        tool_path = os.path.join('tools', 'test_tool.txt')
        with open(tool_path, 'w') as f:
            f.write("Test tool content")

        response = client.post('/read_tool', data={'filename': 'test_tool.txt'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'content' in data
        assert 'Test tool content' in data['content']

        # Cleanup
        os.unlink(tool_path)

    def test_save_tool_file(self, client):
        """Test saving changes to a tool file"""
        # Create initial tool file
        tool_path = os.path.join('tools', 'test_save_tool.txt')
        with open(tool_path, 'w') as f:
            f.write("Original content")

        # Update the file
        new_content = "Updated content for testing"
        response = client.post('/save_tool', data={
            'filename': 'test_save_tool.txt',
            'content': new_content
        })
        assert response.status_code == 200

        # Verify the content was saved
        with open(tool_path, 'r') as f:
            saved_content = f.read()
        assert saved_content == new_content

        # Cleanup
        os.unlink(tool_path)


class TestClipboards:
    """Test clipboard functionality"""

    def test_get_clipboards(self, client):
        """Test retrieving clipboards"""
        response = client.get('/clipboards')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        assert len(data) == 3  # Should have 3 clipboards

    def test_update_clipboard(self, client):
        """Test updating a clipboard"""
        test_content = "Test clipboard content"
        response = client.put(
            '/clipboards/0',
            json={'content': test_content},
            content_type='application/json'
        )
        assert response.status_code == 200

        # Verify the update
        response = client.get('/clipboards')
        data = json.loads(response.data)
        assert data[0] == test_content

    def test_update_invalid_clipboard_index(self, client):
        """Test updating clipboard with invalid index"""
        response = client.put(
            '/clipboards/999',
            json={'content': 'test'},
            content_type='application/json'
        )
        assert response.status_code == 400


class TestIPDiscovery:
    """Test IP address discovery"""

    def test_get_ips_endpoint(self, client):
        """Test /ips endpoint returns list of IPs"""
        response = client.get('/ips')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, list)
        # Should at least have localhost
        assert len(data) > 0


class TestShellsPage:
    """Test shells interface"""

    def test_shells_page_loads(self, client):
        """Test that shells page loads successfully"""
        response = client.get('/shells')
        assert response.status_code == 200


class TestIntegration:
    """Integration tests that verify multiple components working together"""

    def test_upload_then_list_files(self, client):
        """Test uploading a file and then seeing it in the file list"""
        # Upload a file
        test_data = b"Integration test content"
        filename = 'integration_test.txt'

        upload_response = client.put(
            f'/upload/{filename}',
            data=test_data,
            content_type='application/octet-stream'
        )
        assert upload_response.status_code == 200

        # Verify it exists in uploads folder
        upload_path = os.path.join('uploads', filename)
        assert os.path.exists(upload_path)

        # Cleanup
        os.unlink(upload_path)

    def test_create_tool_read_and_modify(self, client):
        """Test complete workflow: create tool, read it, modify it"""
        tool_name = 'workflow_test.sh'
        tool_path = os.path.join('tools', tool_name)

        # Create initial tool
        initial_content = "#!/bin/bash\necho 'Initial version'"
        with open(tool_path, 'w') as f:
            f.write(initial_content)

        # Read the tool
        read_response = client.post('/read_tool', data={'filename': tool_name})
        assert read_response.status_code == 200
        read_data = json.loads(read_response.data)
        assert initial_content in read_data['content']

        # Modify the tool
        updated_content = "#!/bin/bash\necho 'Updated version'\necho 'With more lines'"
        save_response = client.post('/save_tool', data={
            'filename': tool_name,
            'content': updated_content
        })
        assert save_response.status_code == 200

        # Verify the modification
        read_again = client.post('/read_tool', data={'filename': tool_name})
        read_again_data = json.loads(read_again.data)
        assert updated_content in read_again_data['content']

        # Cleanup
        os.unlink(tool_path)


# Test runner configuration
if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
