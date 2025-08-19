# step-kmsproxy-plugin

step-kmsproxy-plugin is an authenticating proxy for mTLS services.  
Think of it like a simple version of [envoy](https://github.com/envoyproxy/envoy),
except keys and certificates are loaded from [Smallstep KMS](https://github.com/smallstep/step-kms-plugin),
which supports numerous HSM backings like YubiKeys, AWS KMS, and TPM 2.0.

On workstations this becomes especially useful, where HSM backed mTLS in
Browsers is barely supported (i.e. using pkcs11-tools, p11kit, and nssdb to
authenticate using YubiKeys or TPMs). Add to that rotating short-lived
certificates and you have a recipe for maintenance disaster.  
However, proxies are seamlessly supported by all major operating systems,
browsers, and most tooling. Leveraging that for authentication means you can
provide an "always logged in" experience that is secured through HSM keys that
can't be extracted from the system (and in case of YubiKeys can be moved between
workstations).

## Installation (Linux)

1. Get the latest binary from releases and place in e.g. `~/.local/bin`.
1. Create a config dir for KMS proxy: `mkdir -p ~/.config/kmsproxy`
1. Create a proxy certificate authority and install it into the system trust store.
   ```
   step certificate create --profile root-ca --no-password --insecure 'Local Smallstep KMS Proxy' ~/.config/kmsproxy/ca.crt ~/.config/kmsproxy/ca.key
   sudo cp ~/.config/kmsproxy/ca.crt /usr/local/share/ca-certificates/step-kmsproxy.crt
   sudo update-ca-certificates
   ```
1. Create a [`ProxyAutoConfiguration.js`](examples/ProxyAutoConfiguration.js)
   file in `~/.config/kmsproxy/ProxyAutoConfiguration.js` that tells the OS &
   browsers which domains to proxy.
1. Setup a [user SystemD service](examples/kmsproxy.service) that starts the KMS proxy
1. Change your OS proxy settings to "Automatic" and set the "Configuration URL"
   to `https://localhost:8091/ProxyAutoConfiguration.js`.  
   Via the terminal:
   ```
   dconf load /system/proxy/ <<'EOF'
   [/]
   mode='auto'
   autoconfig-url='https://localhost:8091/ProxyAutoConfiguration.js'
   EOF
   ```
   Or Gnome Control Center:  
   ![[Proxy configuration in Ubuntu]](examples/ubuntu-proxy-settings.png?raw=true)

## Usage

### Kubernetes

You can use KMS proxy for authenticating with Kubernetes:

1. Extract the cluster CA certificate from your kubeconfig:
   ```
   kubectl config view --raw -ojson | \
     jq -r '.clusters[] | select(.name=="<CLUSTER-NAME>") |
            .cluster["certificate-authority-data"] | @base64d' \
     >~/.config/kmsproxy/<CLUSTER-NAME>.crt
   ```
1. Tell KMS proxy to trust the certificate:
   ```
   ExecStart=%h/.local/bin/step-kmsproxy-plugin ... --cacert %h/.config/kmsproxy/<CLUSTER-NAME>.crt tpmkms:name=mykey
   ```
1. Change your kubeconfig to use KMS proxy:
   ```
   clusters:
   - cluster:
       server: https://api.kube.example.com:6443
       proxy-url: http://localhost:8090
     name: <CLUSTER-NAME>
   ```

### curl

`curl` doesn't integrate with the OS proxy settings and does not support reading
`ProxyAutoConfiguration.js`, so you will need to use the `--proxy` switch or an
[`http_proxy`](https://everything.curl.dev/usingcurl/proxies/env.html)
environment variable.
