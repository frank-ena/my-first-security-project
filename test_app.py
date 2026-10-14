import os
import socket
import unittest
from unittest.mock import patch

import app


class ScanEndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = app.app.test_client()
        self.environment = patch.dict(os.environ, {"SCAN_ACCESS_TOKEN": "test-token"})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()

    def post_scan(self, target):
        return self.client.post(
            "/scan",
            json={"target": target},
            headers={"Authorization": "Bearer test-token"},
        )

    @patch("app.socket.getaddrinfo")
    def test_requires_access_token(self, getaddrinfo):
        response = self.client.post("/scan", json={"target": "127.0.0.1"})

        self.assertEqual(response.status_code, 401)
        getaddrinfo.assert_not_called()

    @patch("app.socket.getaddrinfo")
    def test_reports_missing_server_token_configuration(self, getaddrinfo):
        with patch.dict(os.environ, {}, clear=True):
            response = self.client.post(
                "/scan",
                json={"target": "127.0.0.1"},
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(response.status_code, 503)
        getaddrinfo.assert_not_called()

    @patch("app.socket.socket")
    @patch("app.socket.getaddrinfo")
    def test_rejects_public_target(self, getaddrinfo, create_socket):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))
        ]

        response = self.post_scan("8.8.8.8")

        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.get_json()["success"])
        create_socket.assert_not_called()

    @patch("app.socket.socket")
    @patch("app.socket.getaddrinfo")
    def test_scans_private_target(self, getaddrinfo, create_socket):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.20", 0))
        ]
        create_socket.return_value.__enter__.return_value.connect_ex.return_value = 0

        response = self.post_scan("scanner.local")

        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertTrue(result["success"])
        self.assertEqual(len(result["results"]), len(app.PORTS_TO_SCAN))
        self.assertTrue(all(item["status"] == "OPEN" for item in result["results"]))
        create_socket.assert_called()

    @patch("app.socket.getaddrinfo")
    def test_rejects_hostname_with_public_resolution(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.20", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),
        ]

        response = self.post_scan("mixed.example")

        self.assertEqual(response.status_code, 403)
