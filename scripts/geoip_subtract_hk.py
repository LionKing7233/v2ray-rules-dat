#!/usr/bin/env python3
"""Postprocess a GeoIP DAT by subtracting HK from CN (IPv4 and IPv6)."""

import argparse
import ipaddress
import os
from pathlib import Path
import tempfile


def read_varint(data, pos):
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise ValueError("truncated protobuf varint")
        byte = data[pos]
        pos += 1
        if shift == 63 and byte > 1:
            break
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise ValueError("invalid protobuf varint")


def encode_varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def fields(data):
    pos = 0
    while pos < len(data):
        start = pos
        tag, pos = read_varint(data, pos)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ValueError("invalid protobuf field number")
        if wire == 0:
            value, pos = read_varint(data, pos)
        elif wire == 2:
            length, pos = read_varint(data, pos)
            value = data[pos:pos + length]
            pos += length
        elif wire in (1, 5):
            length = 8 if wire == 1 else 4
            value = data[pos:pos + length]
            pos += length
        else:
            raise ValueError(f"unsupported protobuf wire type: {wire}")
        if pos > len(data):
            raise ValueError("truncated protobuf field")
        yield number, wire, value, data[start:pos]


def message(number, payload):
    return encode_varint(number << 3 | 2) + encode_varint(len(payload)) + payload


def country_code(payload):
    for number, wire, value, _ in fields(payload):
        if number == 1 and wire == 2:
            return value.decode("ascii").upper()
    raise ValueError("GeoIP category has no country code")


def prefixes(payload):
    result = []
    for number, wire, value, _ in fields(payload):
        if number == 3 and wire == 0 and value:
            raise ValueError("CN and HK must not use reverse matching")
        if number != 2 or wire != 2:
            continue
        address, prefix = None, 0
        for child, child_wire, child_value, _ in fields(value):
            if child == 1 and child_wire == 2:
                address = ipaddress.ip_address(child_value)
            elif child == 2 and child_wire == 0:
                prefix = child_value
        if address is None:
            raise ValueError("CIDR has no IP address")
        result.append(ipaddress.ip_network((address, prefix), strict=False))
    return result


def intervals(networks, version):
    result = []
    ranges = sorted((int(n.network_address), int(n.broadcast_address))
                    for n in networks if n.version == version)
    for start, end in ranges:
        if result and start <= result[-1][1] + 1:
            result[-1] = result[-1][0], max(end, result[-1][1])
        else:
            result.append((start, end))
    return result


def subtract(source, excluded):
    result, index = [], 0
    for start, end in source:
        while index < len(excluded) and excluded[index][1] < start:
            index += 1
        cursor, other = start, index
        while other < len(excluded) and excluded[other][0] <= end:
            left, right = excluded[other]
            if cursor < left:
                result.append((cursor, left - 1))
            cursor = max(cursor, right + 1)
            if cursor > end:
                break
            other += 1
        if cursor <= end:
            result.append((cursor, end))
    return result


def postprocess(data):
    top = list(fields(data))
    selected = {}
    cn_index = None
    for index, (number, wire, payload, _) in enumerate(top):
        if number != 1 or wire != 2:
            continue
        code = country_code(payload)
        if code not in ("CN", "HK"):
            continue
        if code in selected:
            raise ValueError(f"duplicate {code} category")
        selected[code] = payload
        if code == "CN":
            cn_index = index
    if set(selected) != {"CN", "HK"}:
        raise ValueError("input must contain both CN and HK categories")

    cn, hk = prefixes(selected["CN"]), prefixes(selected["HK"])
    cleaned, removed = [], {}
    for version, address in ((4, ipaddress.IPv4Address), (6, ipaddress.IPv6Address)):
        source = intervals(cn, version)
        difference = subtract(source, intervals(hk, version))
        removed[version] = (sum(b - a + 1 for a, b in source)
                            - sum(b - a + 1 for a, b in difference))
        for start, end in difference:
            cleaned.extend(ipaddress.summarize_address_range(address(start), address(end)))

    if not any(removed.values()):
        return data, removed
    # Preserve CN metadata, including unknown fields; replace only its CIDRs.
    payload = b"".join(raw for n, w, _, raw in fields(selected["CN"])
                       if not (n == 2 and w == 2))
    for network in cleaned:
        cidr = message(1, network.network_address.packed)
        cidr += b"\x10" + encode_varint(network.prefixlen)
        payload += message(2, cidr)
    replacement = message(1, payload)
    result = b"".join(replacement if i == cn_index else raw
                      for i, (_, _, _, raw) in enumerate(top))
    return result, removed


def write_atomic(output, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=f".{output.name}.",
                                         delete=False) as file:
            temporary = Path(file.name)
            file.write(data)
            file.flush()
            os.fchmod(file.fileno(), 0o644)
            os.fsync(file.fileno())
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="downloaded, unmodified GeoIP DAT")
    parser.add_argument("output", type=Path, help="processed GeoIP DAT (replaced atomically)")
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("input and output must be different files")
    try:
        result, removed = postprocess(args.input.read_bytes())
        write_atomic(args.output, result)
    except (OSError, ValueError) as error:
        parser.exit(1, f"error: {error}\n")
    for version in (4, 6):
        print(f"IPv{version}: removed {removed[version]} addresses overlapping HK")
    print(f"Written: {args.output}")


if __name__ == "__main__":
    main()
