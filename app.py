
import errno
import hmac
import ipaddress
import os
import socket
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

ALLOWED_TARGET_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    )
)
PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 8080]


class DisallowedTargetError(Exception):
    pass


@app.route("/")
def home():
    return render_template("index.html")


def resolve_allowed_target(target_host):
    addresses = socket.getaddrinfo(target_host, None, type=socket.SOCK_STREAM)
    unique_addresses = {}

    for family, _, _, _, sockaddr in addresses:
        address = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped
            family = socket.AF_INET

        if not any(address in network for network in ALLOWED_TARGET_NETWORKS):
            raise DisallowedTargetError(
                "Only localhost and private-network targets are allowed."
            )

        normalized_sockaddr = (
            (str(address), sockaddr[1])
            if family == socket.AF_INET
            else (str(address), *sockaddr[1:])
        )
        unique_addresses[(family, normalized_sockaddr)] = (family, normalized_sockaddr)

    if not unique_addresses:
        raise socket.gaierror("The target hostname did not resolve to an IP address.")

    return list(unique_addresses.values())


def scan_port(addresses, port):
    results = []
    for family, sockaddr in addresses:
        target = (sockaddr[0], port, *sockaddr[2:]) if family == socket.AF_INET6 else (sockaddr[0], port)
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(1.0)
            results.append(connection.connect_ex(target))

    if 0 in results:
        return "OPEN"
    if errno.ETIMEDOUT in results:
        return "TIMEOUT"
    if results and all(result == errno.ECONNREFUSED for result in results):
        return "CLOSED"
    return "UNREACHABLE"


@app.route("/scan", methods=["POST"])
def scan_ports():
    access_token = os.environ.get("SCAN_ACCESS_TOKEN")
    if not access_token:
        app.logger.error("SCAN_ACCESS_TOKEN is not configured")
        return jsonify({"success": False, "error": "Scanning is not configured."}), 503

    authorization = request.headers.get("Authorization", "")
    provided_token = authorization.removeprefix("Bearer ").strip()
    if not authorization.startswith("Bearer ") or not hmac.compare_digest(
        provided_token.encode("utf-8"), access_token.encode("utf-8")
    ):
        return jsonify({"success": False, "error": "A valid access token is required."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "error": "Request must contain a JSON object."}), 400

    target_host = data.get("target")
    if not isinstance(target_host, str):
        return jsonify({"success": False, "error": "Target must be a hostname or IP address."}), 400

    target_host = target_host.strip()
    if (
        not target_host
        or len(target_host) > 253
        or any(character.isspace() or ord(character) < 32 for character in target_host)
    ):
        return jsonify({"success": False, "error": "Enter a valid hostname or IP address."}), 400

    try:
        addresses = resolve_allowed_target(target_host)
        scan_results = [
            {"port": port, "status": scan_port(addresses, port)}
            for port in PORTS_TO_SCAN
        ]
        return jsonify({"success": True, "results": scan_results})

    except DisallowedTargetError as error:
        return jsonify({"success": False, "error": str(error)}), 403
    except socket.gaierror:
        return jsonify({"success": False, "error": "The target hostname could not be resolved."}), 400
    except OSError:
        app.logger.exception("Port scan failed")
        return jsonify({"success": False, "error": "The scan could not be completed."}), 500


if __name__ == "__main__":
    app.run(debug=False)