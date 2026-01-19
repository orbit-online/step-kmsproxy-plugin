// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file
function FindProxyForURL(url, host) {
  if (shExpMatch(host, "*.ops.example.com|*.backend.example.com")) {
    return "HTTPS 127.0.0.1:8090";
  }
  return "DIRECT";
}
