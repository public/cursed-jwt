#!/usr/bin/env python3
"""make_configs.py JWKS OUTDIR: Envoy v1.40.2 bootstrap configs for the functional test and load runs (JSON, which
Envoy reads as YAML).  One listener on :10000; every config answers GET / with a 200 direct_response, so a run
measures Envoy + the auth filter and nothing else.

  none          no auth filter (the floor)
  jwt_authn     envoy.filters.http.jwt_authn: one provider, local JWKS, issuer + audience, forward_payload_header
  jwt_authn_c   the same with jwt_cache_config (verified tokens cached by token string, default size 100)
  cjwt          our dynamic module (libcjwt_authn.so) with the same provider settings
  dm_noop       the same module doing nothing (returns Continue): the cost of the dynamic-modules route itself
"""

import copy
import json
import os
import sys

jwks = open(sys.argv[1]).read().strip()
out = sys.argv[2]
os.makedirs(out, exist_ok=True)

ISS, AUD = "https://auth.example.com/", "https://api.example.com"
ROUTER = {
    "name": "envoy.filters.http.router",
    "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"},
}
# the echo headers let the functional check see what the auth filter forwarded (payload header, token removed)
DIRECT = {
    "match": {"prefix": "/"},
    "direct_response": {"status": 200, "body": {"inline_string": "ok\n"}},
    "response_headers_to_add": [
        {"header": {"key": "x-seen-payload", "value": "%REQ(x-jwt-payload)%"}},
        {"header": {"key": "x-seen-auth", "value": "%REQ(authorization)%"}},
    ],
}


def listener(name, port, filters, route=DIRECT):
    return {
        "name": name,
        "address": {"socket_address": {"address": "0.0.0.0", "port_value": port}},
        "filter_chains": [
            {
                "filters": [
                    {
                        "name": "envoy.filters.network.http_connection_manager",
                        "typed_config": {
                            "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                            "stat_prefix": name,
                            "codec_type": "HTTP1",
                            "route_config": {"virtual_hosts": [{"name": "all", "domains": ["*"], "routes": [route]}]},
                            "http_filters": filters + [ROUTER],
                        },
                    }
                ]
            }
        ],
    }


def bootstrap(listeners):
    return {
        "admin": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9901}}},
        "static_resources": {"listeners": listeners, "clusters": []},
        "layered_runtime": {"layers": [{"name": "static", "static_layer": {}}]},
    }


provider = {
    "issuer": ISS,
    "audiences": [AUD],
    "local_jwks": {"inline_string": jwks},
    "forward_payload_header": "x-jwt-payload",
}
jwt_authn = {
    "name": "envoy.filters.http.jwt_authn",
    "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication",
        "providers": {"p": provider},
        "rules": [{"match": {"prefix": "/"}, "requires": {"provider_name": "p"}}],
    },
}
jwt_authn_c = copy.deepcopy(jwt_authn)
jwt_authn_c["typed_config"]["providers"]["p"]["jwt_cache_config"] = {"jwt_cache_size": 100}
cjwt = {
    "name": "envoy.filters.http.dynamic_modules",
    "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
        "dynamic_module_config": {"name": "cjwt_authn"},
        "filter_name": "cjwt",
        "filter_config": {
            "@type": "type.googleapis.com/google.protobuf.Struct",
            "value": {
                "issuer": ISS,
                "audiences": [AUD],
                "jwks": json.loads(jwks),
                "forward_payload_header": "x-jwt-payload",
            },
        },
    },
}
dm_noop = {
    "name": "envoy.filters.http.dynamic_modules",
    "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter",
        "dynamic_module_config": {"name": "cjwt_authn"},
        "filter_name": "cjwt",
        "filter_config": {"@type": "type.googleapis.com/google.protobuf.Struct", "value": {"noop": True}},
    },
}
configs = {
    "none": bootstrap([listener("main", 10000, [])]),
    "jwt_authn": bootstrap([listener("main", 10000, [jwt_authn])]),
    "jwt_authn_c": bootstrap([listener("main", 10000, [jwt_authn_c])]),
    "cjwt": bootstrap([listener("main", 10000, [cjwt])]),
    "dm_noop": bootstrap([listener("main", 10000, [dm_noop])]),
}
for name, cfg in configs.items():
    with open(os.path.join(out, name + ".json"), "w") as f:
        json.dump(cfg, f, indent=1)
print("wrote", ", ".join(sorted(configs)), "to", out)
