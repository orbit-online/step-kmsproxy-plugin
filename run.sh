#!/usr/bin/env bash
go build
./step-kmsproxy-plugin \
  --trust /nix/store/130arqw6xyzlxl5axpwgx0i72wzmm3wg-ops.orbit.dev.crt \
  --trust /nix/store/ql8704k89srvrrbypn4b6cbjpqv7b5pn-ops-staging.orbit.dev.crt \
  --trust /nix/store/7bbz4hs17f2v9kz6p8rdyqp3fkgcphcn-ops-staging.orbit.dev.crt \
  --pac /nix/store/40qvks561hlw389fmgx7r4gsgczh4vkm-ProxyAutoConfiguration.js \
  --clientcert "$HOME/.step/certs/cloud-production.crt" \
  --cacert "/nix/store/6v56paz89kmj484ailrpfn07nvdxn8ia-local-ca.crt" \
  --listen="tcp:localhost:8090" --pac-port=8091 \
  tpmkms:name=cloud-production \
  "tpmkms:storage-directory=/var/lib/local-ca;name=local-ca" \
  --verbose
