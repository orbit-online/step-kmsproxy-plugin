package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/orbit-online/step-kmsproxy-plugin/kmsproxy"
	"golang.org/x/sync/errgroup"

	// KMS modules (https://github.com/smallstep/step-kms-plugin/blob/3be48fd238cdc1d40dfad5e6410cf852544c3b4f/main.go#L19-L29)
	_ "go.step.sm/crypto/kms/awskms"
	_ "go.step.sm/crypto/kms/azurekms"
	_ "go.step.sm/crypto/kms/capi"
	_ "go.step.sm/crypto/kms/cloudkms"
	_ "go.step.sm/crypto/kms/mackms"
	_ "go.step.sm/crypto/kms/pkcs11"
	_ "go.step.sm/crypto/kms/softkms"
	_ "go.step.sm/crypto/kms/sshagentkms"
	_ "go.step.sm/crypto/kms/tpmkms"
	_ "go.step.sm/crypto/kms/yubikey"
)

type Params struct {
	ClientKey          string   `required:"" arg:"" name:"clientkey" help:"Filesystem path or Smallstep KMS key URI to use for mTLS connections"`
	CAKey              string   `required:"" arg:"" name:"cakey" help:"Filesystem path or Smallstep KMS key URI used for creating certificates trusted by proxy clients"`
	ClientCert         *string  `name:"clientcert" help:"Path to client certificate matching the key at <clientkey> (defaults to using <clientkey>)"`
	CACert             *string  `name:"cacert" help:"Path to CA certificate matching the key at <cakey> (defaults to using <cakey>)"`
	Trust              []string `name:"trust" help:"CA bundle to trust beyond the system trust store, can be specified multiple times." type:"path"`
	Listen             string   `help:"Listening address" type:"string" default:"localhost:8090"`
	PACListen          string   `help:"Listening address for serving AutoProxyConfiguration.js" default:"localhost:8091"`
	PAC                *string  `help:"Path to AutoProxyConfiguration.js" type:"path"`
	InsecureSkipVerify bool     `help:"Disable validation of server certificates"`
	Verbose            bool     `help:"Turn on verbose logging"`
}

var params Params

func main() {
	kong.Parse(&params, kong.Name("step-kmsproxy-plugin"), kong.Description("Use smallstep to create mTLS tunnels"))
	slog.SetDefault(slog.Default())
	if params.Verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	err := startProxy(context.Background(), params)
	if err != nil {
		log.Fatal(err)
	}
}

func startProxy(ctx context.Context, params Params) error {
	var wg errgroup.Group
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)
	proxy, err := kmsproxy.NewProxy(ctx, params.CAKey, params.CACert, params.Trust, params.ClientKey, params.ClientCert, params.InsecureSkipVerify, params.PAC)
	if err != nil {
		return err
	}
	wg.Go(func() error { return proxy.WatchClientCert(ctx, sigs) })
	if params.PAC != nil {
		wg.Go(func() error { return proxy.ServePAC(params.PACListen) })
	}
	wg.Go(func() error { return proxy.Serve(params.Listen) })
	slog.Info("Startup completed")
	if err := wg.Wait(); err != nil {
		return err
	}
	return nil
}
