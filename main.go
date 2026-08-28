package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	path_poller "github.com/orbit-online/go-path-poller"
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
	CAKeyPath          string   `required:"" arg:"" name:"cakey" help:"Filesystem path or Smallstep KMS key URI used for creating certificates trusted by proxy clients"`
	CACertPath         string   `required:"" arg:"" name:"cacert" help:"Path to CA certificate matching the key at <cakey>"`
	ClientKeyPaths     []string `required:"" name:"clientkey" help:"Filesystem paths or Smallstep KMS key URIs to use for mTLS connections"`
	ClientCertPaths    []string `required:"" name:"clientcert" help:"Path to client certificates matching the keys from --clientkey"`
	TrustBundlePaths   []string `name:"trust" help:"CA bundle to trust beyond the system trust store, can be specified multiple times." type:"path"`
	ListenAddr         string   `name:"listen" help:"Listening address, empty string to disable" type:"string" default:"localhost:8090"`
	PACListenAddr      string   `name:"pac-listen" help:"Listening address for serving AutoProxyConfiguration.js" default:"localhost:8091"`
	PACPath            *string  `name:"pac" help:"Path to AutoProxyConfiguration.js" type:"path"`
	RevListenAddr      string   `name:"rev-listen" help:"Reverse proxy listening address, empty string to disable" type:"string" default:"localhost:8092"`
	RevSuffixes        []string `name:"rev-suffix" help:"Suffixes to strip from reverse proxied domains" type:"string" default:".kmsproxy.internal"`
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
	ret := 0
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			ret = 1
			slog.Error(err.Error())
		}
	}
	os.Exit(ret)
}

func startProxy(parentCtx context.Context, params Params) error {
	wg, groupCtx := errgroup.WithContext(parentCtx)

	ctx, stop := signal.NotifyContext(groupCtx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pathNotifier, err := path_poller.NewPathNotifier()
	if err != nil {
		return err
	}

	proxy, err := kmsproxy.NewProxy(ctx, params.CAKeyPath, params.CACertPath, params.TrustBundlePaths, params.ClientKeyPaths, params.ClientCertPaths, params.InsecureSkipVerify, params.PACPath, pathNotifier)
	if err != nil {
		return err
	}

	reloadSig := make(chan os.Signal, 1)
	signal.Notify(reloadSig, syscall.SIGHUP)
	wg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-reloadSig:
				proxy.LoadClientKeyCerts(ctx, "SIGHUP reload signal was sent")
			}
		}
	})

	wg.Go(func() error { return pathNotifier.Run(ctx) })

	if params.PACPath != nil {
		wg.Go(func() error { return proxy.ServePAC(ctx, params.PACListenAddr) })
	}

	if params.ListenAddr != "" {
		wg.Go(func() error { return proxy.ServeHTTPSProxyRequests(ctx, params.ListenAddr) })
	}

	if params.RevListenAddr != "" {
		wg.Go(func() error { return proxy.ServeReverseProxyRequests(ctx, params.RevListenAddr, params.RevSuffixes) })
	}

	slog.Info("Startup completed")
	return wg.Wait()
}
