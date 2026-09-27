#!/usr/bin/env python3
import json,sys
p=sys.argv[1] if len(sys.argv)>1 else 'config/kong-runtime-config-mode.v1.json';x=json.load(open(p))
assert x['production_mode']=='hybrid'
assert x['fallback_mode']=='traditional' and x['fallback_requires_explicit_approval'] is True
assert x['standalone_dbless_production'] is False
assert x['declarative_config_role']=='validation-and-source-generation-only'
assert x['admin_api']['public'] is False and x['admin_api']['proxy_data_plane']=='disabled'
assert x['hybrid_cluster']=={'mtls':True,'pki':'private','ports':[8005,8006]}
assert x['runtime_apply_authorized'] is False
print('kong-runtime-mode: PASS')
