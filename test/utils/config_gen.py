'''
LF config generation script:
Generates LF configuration with a specific number of ASes.
'''

import json
import argparse

ISD_MAX = 1
AS_MAX = 1

template_config = {
    "isd_as": "1-1",
    "port": 49149,
    "ratelimit": {
        "byte_rate": 9223372036854775807,
        "packet_rate": 9223372036854775807
    },
    "peers": [],
    "inbound": {
        "ether": "98:03:9b:79:bb:54"
    },
    "outbound": {
        "ether": "98:03:9b:79:bb:54"
    }
}

template_peer = {
    "isd_as": "0-0",
    "drkey_protocol": 3,
    "ratelimit": {
        "byte_rate": 9223372036854775807,
        "packet_rate": 9223372036854775807
    }
}

def gen_config():
    peers = []

    for isd_n in range(1, ISD_MAX + 1):
        for as_n in range(1, AS_MAX + 1):
            peer = template_peer.copy()
            peer['isd_as'] = f"{isd_n}-{as_n}"
            peers.append(peer)

    config = template_config.copy()
    config['peers'] = peers
    return config

def main(args):
    config = gen_config()
    json_object = json.dumps(config, indent=4)
    if (args.out):
        with open(args.out, 'w') as f:
            f.write(json_object)
    else:
        print(json_object)

parser = argparse.ArgumentParser(description='LF config generator script.')
parser.add_argument('--out', help='output file (otherwise stdout)')

args = parser.parse_args()

main(args)