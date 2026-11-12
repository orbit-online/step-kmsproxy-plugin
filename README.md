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

## Who may use the proxy

The proxy listens on localhost, so any local process could otherwise use the
client certificates. Before a caller reaches a domain for the first time, the
proxy asks: "Always allow", "Allow for 1 hour" or "Deny" (remembered for an
hour). Requests from one caller wait for one question, which lists every domain
they wait on. A request gives up after 2 minutes or when its client hangs up.
"Always allow" answers are kept in `<config dir>/kmsproxy/allowed.json`
(`~/.config` on Linux), one caller and domain per entry.

What counts as one caller depends on the OS:

- Linux: the uid and cgroup of the client socket, from sock_diag, with instance
  ids dropped (`app-gnome-firefox-1234.scope` is `app-gnome-firefox.scope`),
  the executable names (from `/proc/<pid>/exe`, without Nix wrapper
  decorations), and whether the process runs in a user or mount namespace
  other than the proxy. Within a cgroup the executable is a label, not a
  boundary. The question is a desktop notification; on COSMIC, which shows no
  buttons, a click on it opens a zenity dialog.
- macOS: the code signature (designated requirement) and App Sandbox flag of
  the client process, found with `lsof` and `codesign`. The question is an
  alert from `osascript`.
- Windows: the user, AppContainer and executable of the client process. The
  question is a task dialog.

"Always allow" isn't offered for a caller the OS couldn't inspect, e.g. a
process of your own that made itself unreadable (`exe=unknown ns=unknown`);
on Linux root is the exception, since only root owns a socket as uid 0.

`--allow FILE` adds read-only rules in the same format, e.g. a default list
shipped with the system; they aren't written to `allowed.json`. `--no-gate`
turns the gate off.

The model of the rules and prompts is in [`models/gate.als`](models/gate.als);
`models/run.sh` checks it.

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
   ExecStart=%h/.local/bin/step-kmsproxy-plugin ... --trust %h/.config/kmsproxy/<CLUSTER-NAME>.crt tpmkms:name=mykey
   ```
1. Change your kubeconfig to use KMS proxy:
   ```
   clusters:
   - cluster:
       server: https://api.kube.example.com:6443
       proxy-url: https://localhost:8090
     name: <CLUSTER-NAME>
   ```

### curl

`curl` doesn't integrate with the OS proxy settings and does not support reading
`ProxyAutoConfiguration.js`, so you will need to use the `--proxy` switch or an
[`http_proxy`](https://everything.curl.dev/usingcurl/proxies/env.html)
environment variable.
