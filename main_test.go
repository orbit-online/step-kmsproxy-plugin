package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func parse(t *testing.T, args ...string) (Params, error) {
	t.Helper()
	var p Params
	parser, err := newParser(&p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = parser.Parse(args)
	return p, err
}

func writeConfig(t *testing.T, json string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kmsproxy.json")
	if err := os.WriteFile(path, []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestArguments(t *testing.T) {
	p, err := parse(t, "--clientkey=k", "--clientcert=c", "ca.key", "ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	if p.CAKeyPath != "ca.key" || p.CACertPath != "ca.crt" {
		t.Errorf("CA %q %q", p.CAKeyPath, p.CACertPath)
	}
	if p.ListenAddr != "localhost:8090" || p.PACListenAddr != "localhost:8091" {
		t.Errorf("defaults %q %q", p.ListenAddr, p.PACListenAddr)
	}
}

func TestConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, `{
		"cakey": "mackms:label=local-ca",
		"cacert": "/ca.crt",
		"clientkey": ["sshagentkms:a", "sshagentkms:b"],
		"clientcert": ["/staging.crt", "/production.crt"],
		"trust": ["`+dir+`/machines_ca.crt"],
		"listen": "localhost:9000",
		"pac_listen": "localhost:9001",
		"pac": "`+dir+`/pac.js",
		"revListen": "",
		"verbose": true
	}`)
	p, err := parse(t, "--config", path)
	if err != nil {
		t.Fatal(err)
	}
	if p.CAKeyPath != "mackms:label=local-ca" || p.CACertPath != "/ca.crt" {
		t.Errorf("CA %q %q", p.CAKeyPath, p.CACertPath)
	}
	if !reflect.DeepEqual(p.ClientKeyPaths, []string{"sshagentkms:a", "sshagentkms:b"}) {
		t.Errorf("clientkey %q", p.ClientKeyPaths)
	}
	if !reflect.DeepEqual(p.ClientCertPaths, []string{"/staging.crt", "/production.crt"}) {
		t.Errorf("clientcert %q", p.ClientCertPaths)
	}
	if !reflect.DeepEqual(p.TrustBundlePaths, []string{dir + "/machines_ca.crt"}) {
		t.Errorf("trust %q", p.TrustBundlePaths)
	}
	if p.ListenAddr != "localhost:9000" || p.PACListenAddr != "localhost:9001" || p.RevListenAddr != "" {
		t.Errorf("listen %q %q %q", p.ListenAddr, p.PACListenAddr, p.RevListenAddr)
	}
	if p.PACPath == nil || *p.PACPath != dir+"/pac.js" {
		t.Errorf("pac %v", p.PACPath)
	}
	if !p.Verbose {
		t.Error("verbose not set")
	}
}

func TestCommandLineOverridesConfig(t *testing.T) {
	path := writeConfig(t, `{"cakey": "a", "cacert": "b", "clientkey": ["k"], "clientcert": ["c"], "listen": "localhost:9000"}`)
	p, err := parse(t, "--config", path, "--listen", "localhost:7000")
	if err != nil {
		t.Fatal(err)
	}
	if p.ListenAddr != "localhost:7000" {
		t.Errorf("listen %q", p.ListenAddr)
	}
}

func TestCAArgumentsOrFlags(t *testing.T) {
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"--clientkey=k", "--clientcert=c"}, "are missing"},
		{[]string{"--clientkey=k", "--clientcert=c", "ca.key"}, "<cacert> is missing"},
		{[]string{"--clientkey=k", "--clientcert=c", "--cakey=a", "ca.key", "ca.crt"}, "not both"},
		{[]string{"--clientkey=k", "--clientcert=c", "--cakey=a"}, "are missing"},
		{[]string{"--clientkey=k", "--clientcert=c", "--cakey=a", "--cacert=b"}, ""},
	} {
		_, err := parse(t, tc.args...)
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%q: %v, want %q", tc.args, err, tc.err)
		}
	}
}

func TestConfigFileMissingOrBroken(t *testing.T) {
	if _, err := parse(t, "--config", filepath.Join(t.TempDir(), "none.json")); err == nil {
		t.Error("a missing config file passed")
	}
	if _, err := parse(t, "--config", writeConfig(t, `{"cakey": `)); err == nil {
		t.Error("a broken config file passed")
	}
}
