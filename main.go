package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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
	Config             kong.ConfigFlag `name:"config" help:"JSON file of flag values by flag name, dashes as underscores, e.g. {\"clientkey\": [\"...\"], \"pac_listen\": \"localhost:8091\"}; the command line wins" type:"path"`
	CAKeyArg           string          `arg:"" optional:"" name:"cakey" help:"Filesystem path or Smallstep KMS key URI used for creating certificates trusted by proxy clients (or --cakey)"`
	CACertArg          string          `arg:"" optional:"" name:"cacert" help:"Path to CA certificate matching the key at <cakey> (or --cacert)"`
	CAKeyPath          string          `name:"cakey" help:"<cakey> as a flag, which --config can set"`
	CACertPath         string          `name:"cacert" help:"<cacert> as a flag, which --config can set"`
	ClientKeyPaths     []string        `required:"" name:"clientkey" help:"Filesystem paths or Smallstep KMS key URIs to use for mTLS connections"`
	ClientCertPaths    []string        `required:"" name:"clientcert" help:"Path to client certificates matching the keys from --clientkey"`
	TrustBundlePaths   []string        `name:"trust" help:"CA bundle to trust beyond the system trust store, can be specified multiple times." type:"path"`
	ListenAddr         string          `name:"listen" help:"Listening address, empty string to disable" type:"string" default:"localhost:8090"`
	PACListenAddr      string          `name:"pac-listen" help:"Listening address for serving AutoProxyConfiguration.js" default:"localhost:8091"`
	PACPath            *string         `name:"pac" help:"Path to AutoProxyConfiguration.js" type:"path"`
	RevListenAddr      string          `name:"rev-listen" help:"Reverse proxy listening address, empty string to disable" type:"string" default:"localhost:8092"`
	RevSuffixes        []string        `name:"rev-suffix" help:"Suffixes to strip from reverse proxied domains" type:"string" default:".kmsproxy.internal"`
	RevPortMap         []string        `name:"rev-portmap" help:"DOMAIN=PORT mappings that should connect to a port other than 443 (e.g. --rev-portmap example.com.kmsproxy.internal=3000)" type:"string"`
	InsecureSkipVerify bool            `help:"Disable validation of server certificates"`
	Verbose            bool            `help:"Turn on verbose logging"`
	LogFile            string          `name:"log-file" help:"Append the log to this file instead of stderr; at start, a file past 1 MiB moves to <file>.old" type:"path"`
}

// Validate takes the CA key and certificate from the arguments or from the
// flags, not both. A config file sets only flags: kong resolves flags from
// it, never arguments.
func (p *Params) Validate() error {
	if p.CAKeyArg != "" || p.CACertArg != "" {
		if p.CAKeyPath != "" || p.CACertPath != "" {
			return errors.New("the CA key and certificate are either <cakey> <cacert> or --cakey and --cacert, not both")
		}
		if p.CACertArg == "" {
			return errors.New("<cacert> is missing")
		}
		p.CAKeyPath, p.CACertPath = p.CAKeyArg, p.CACertArg
	}
	if p.CAKeyPath == "" || p.CACertPath == "" {
		return errors.New("the CA key and certificate are missing: <cakey> <cacert>, or --cakey and --cacert")
	}
	return nil
}

func newParser(params *Params, options ...kong.Option) (*kong.Kong, error) {
	return kong.New(params, append([]kong.Option{
		kong.Name("step-kmsproxy-plugin"),
		kong.Description("Use smallstep to create mTLS tunnels"),
		kong.Configuration(kong.JSON),
	}, options...)...)
}

var params Params

func main() {
	parser, err := newParser(&params)
	if err != nil {
		panic(err)
	}
	_, err = parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)
	if params.LogFile != "" {
		f, err := openLog(params.LogFile)
		parser.FatalIfErrorf(err)
		defer f.Close()
		log.SetOutput(f)
	}
	slog.SetDefault(slog.Default())
	if params.Verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	err = startProxy(context.Background(), params)
	ret := 0
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			ret = 1
			slog.Error(err.Error())
		}
	}
	os.Exit(ret)
}

// openLog opens path to append to, moving it to path.old first when it is
// past 1 MiB.
func openLog(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() > 1<<20 {
		if err := os.Rename(path, path+".old"); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
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
				proxy.ForgetTPMKeys()
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
		wg.Go(func() error {
			portMap := map[string]int64{}
			for _, mapping := range params.RevPortMap {
				split := strings.SplitN(mapping, "=", 2)
				if len(split) != 2 {
					return fmt.Errorf("Invalid --rev-portmap %s, must be DOMAIN=PORT", mapping)
				}
				if portMap[split[0]], err = strconv.ParseInt(split[1], 10, 32); err != nil {
					return err
				}
			}
			return proxy.ServeReverseProxyRequests(ctx, params.RevListenAddr, params.RevSuffixes, portMap)
		})
	}

	slog.Info("Startup completed")
	return wg.Wait()
}
