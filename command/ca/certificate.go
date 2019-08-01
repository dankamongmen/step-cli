package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/command"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/flags"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/token"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/smallstep/cli/utils/cautils"
	"github.com/urfave/cli"
)

func certificateCommand() cli.Command {
	return cli.Command{
		Name:   "certificate",
		Action: command.ActionFunc(certificateAction),
		Usage:  "generate a new private key and certificate signed by the root certificate",
		UsageText: `**step ca certificate** <subject> <crt-file> <key-file>
[**--token**=<token>]  [**--issuer**=<name>] [**--ca-url**=<uri>] [**--root**=<file>]
[**--not-before**=<time|duration>] [**--not-after**=<time|duration>]
[**--san**=<SAN>] [**--acme**] [**--standalone**] [**--webroot**=<path>]
[**--contact**=<email>] [*--http-port*=<port>], [**--kty**=<type>]
[**--curve**=<curve>] [**--size**=<size>] [**--console**]`,
		Description: `**step ca certificate** command generates a new certificate pair

## POSITIONAL ARGUMENTS

<subject>
:  The Common Name, DNS Name, or IP address that will be set as the
Subject Common Name for the certificate. If no Subject Alternative Names (SANs)
are configured (via the --san flag) then the <subject> will be set as the only SAN.

<crt-file>
:  File to write the certificate (PEM format)

<key-file>
:  File to write the private key (PEM format)

## EXAMPLES

Request a new certificate for a given domain. There are no additional SANs
configured, therefore (by default) the <subject> will be used as the only
SAN extension: DNS Name internal.example.com:
'''
$ TOKEN=$(step ca token internal.example.com)
$ step ca certificate --token $TOKEN internal.example.com internal.crt internal.key
'''

Request a new certificate with multiple Subject Alternative Names. The Subject
Common Name of the certificate will be 'foobar'. However, because additional SANs are
configured using the --san flag and 'foobar' is not one of these, 'foobar' will
not be in the SAN extensions of the certificate. The certificate will have 2
IP Address extensions (1.1.1.1, 10.2.3.4) and 1 DNS Name extension (hello.example.com):
'''
$ step ca certificate --san 1.1.1.1 --san hello.example.com --san 10.2.3.4 foobar internal.crt internal.key
'''

Request a new certificate with a 1h validity:
'''
$ TOKEN=$(step ca token internal.example.com)
$ step ca certificate --token $TOKEN --not-after=1h internal.example.com internal.crt internal.key
'''

Request a new certificate using the offline mode, requires the configuration
files, certificates, and keys created with **step ca init**:
'''
$ step ca certificate --offline internal.example.com internal.crt internal.key
'''

Request a new certificate using an OIDC provisioner:
'''
$ step ca certificate --token $(step oauth --oidc --bare) joe@example.com joe.crt joe.key
'''

Request a new certificate using an OIDC provisioner while remaining in the console:
'''
$ step ca certificate joe@example.com joe.crt joe.key --issuer Google --console
'''

Request a new certificate with an RSA public key (default is ECDSA256):
'''
$ step ca certificate foo.internal foo.crt foo.key --kty RSA --size 4096

Request a new certificate using the step CA ACME server and a standalone server
to serve the challenges locally:
'''
$ step ca certificate foobar foo.crt foo.key --acme --standalone \
--san foo.internal --san bar.internal

Request a new certificate using the step CA ACME server and an existing server
along with webroot mode to serve the challenges locally:
'''
$ step ca certificate foobar foo.crt foo.key --acme --webroot "./acme-www" \
--san foo.internal --san bar.internal
'''`,
		Flags: []cli.Flag{
			consoleFlag,
			flags.CaConfig,
			flags.CaURL,
			flags.Curve,
			flags.Force,
			flags.KTY,
			flags.NotAfter,
			flags.NotBefore,
			flags.Provisioner,
			flags.Root,
			flags.Size,
			flags.Token,
			flags.Offline,
			cli.StringSliceFlag{
				Name: "san",
				Usage: `Add DNS Name, IP Address, or Email Address Subjective Alternative Names (SANs)
that the token is authorized to request. A certificate signing request using
this token must match the complete set of subjective alternative names in the
token 1:1. Use the '--san' flag multiple times to configure multiple SANs. The
'--san' flag and the '--token' flag are mutually exlusive.`,
			},
			cli.BoolFlag{
				Name:  "acme",
				Usage: `Use the ACME protocol to get a certificate.`,
			},
			cli.BoolFlag{
				Name: "standalone",
				Usage: `Run a standalone webserver for ACME authentication. Must be used in conjunction
with the --acme flag.`,
			},
			cli.StringFlag{
				Name: "webroot",
				Usage: `Run a standalone webserver for ACME authentication. Must be used in conjunction
with the --acme flag.`,
			},
			cli.StringSliceFlag{
				Name: "contact",
				Usage: `Email addresses for contact as part of the ACME protocol. These contacts
may be used to warn of certificate expration or other certificate lifetime events.`,
			},
			cli.IntFlag{
				Name:  "http-port",
				Usage: `Use a non-standard http port behind a reverse proxy or load balancer. (default is 80)`,
				Value: 80,
			},
		},
	}
}

func certificateAction(ctx *cli.Context) error {
	if err := errs.NumberOfArguments(ctx, 3); err != nil {
		return err
	}

	if ctx.Bool("acme") {
		return acmeFlow(ctx)
	}

	args := ctx.Args()
	subject := args.Get(0)
	crtFile, keyFile := args.Get(1), args.Get(2)

	tok := ctx.String("token")
	offline := ctx.Bool("offline")
	sans := ctx.StringSlice("san")

	// offline and token are incompatible because the token is generated before
	// the start of the offline CA.
	if offline && len(tok) != 0 {
		return errs.IncompatibleFlagWithFlag(ctx, "offline", "token")
	}

	// certificate flow unifies online and offline flows on a single api
	flow, err := cautils.NewCertificateFlow(ctx)
	if err != nil {
		return err
	}

	if len(tok) == 0 {
		if tok, err = flow.GenerateToken(ctx, subject, sans); err != nil {
			return err
		}
	}

	req, pk, err := flow.CreateSignRequest(ctx, tok, subject, sans)
	if err != nil {
		return err
	}

	jwt, err := token.ParseInsecure(tok)
	if err != nil {
		return err
	}

	switch jwt.Payload.Type() {
	case token.JWK: // Validate that subject matches the CSR common name.
		if ctx.String("token") != "" && len(sans) > 0 {
			return errs.MutuallyExclusiveFlags(ctx, "token", "san")
		}
		if strings.ToLower(subject) != strings.ToLower(req.CsrPEM.Subject.CommonName) {
			return errors.Errorf("token subject '%s' and argument '%s' do not match", req.CsrPEM.Subject.CommonName, subject)
		}
	case token.OIDC: // Validate that the subject matches an email SAN
		if len(req.CsrPEM.EmailAddresses) == 0 {
			return errors.New("unexpected token: payload does not contain an email claim")
		}
		if email := req.CsrPEM.EmailAddresses[0]; email != subject {
			return errors.Errorf("token email '%s' and argument '%s' do not match", email, subject)
		}
	case token.AWS, token.GCP, token.Azure:
		// Common name will be validated on the server side, it depends on
		// server configuration.
	default:
		return errors.New("token is not supported")
	}

	if err = flow.Sign(ctx, tok, req.CsrPEM, crtFile); err != nil {
		return err
	}

	_, err = pemutil.Serialize(pk, pemutil.ToFile(keyFile, 0600))
	if err != nil {
		return err
	}

	ui.PrintSelected("Certificate", crtFile)
	ui.PrintSelected("Private Key", keyFile)
	return nil
}

type certificateFlow struct {
	offlineCA *offlineCA
	offline   bool
}

func newCertificateFlow(ctx *cli.Context) (*certificateFlow, error) {
	var err error
	var offlineClient *offlineCA

	offline := ctx.Bool("offline")
	if offline {
		caConfig := ctx.String("ca-config")
		if caConfig == "" {
			return nil, errs.InvalidFlagValue(ctx, "ca-config", "", "")
		}
		offlineClient, err = newOfflineCA(caConfig)
		if err != nil {
			return nil, err
		}
	}

	return &certificateFlow{
		offlineCA: offlineClient,
		offline:   offline,
	}, nil
}

func (f *certificateFlow) getClient(ctx *cli.Context, subject, tok string) (caClient, error) {
	if f.offline {
		return f.offlineCA, nil
	}

	// Create online client
	root := ctx.String("root")
	caURL := ctx.String("ca-url")

	jwt, err := token.ParseInsecure(tok)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing flag '--token'")
	}
	switch jwt.Payload.Type() {
	case token.AWS, token.GCP, token.Azure:
		// Common name will be validated on the server side, it depends on
		// server configuration.
	default:
		if strings.ToLower(jwt.Payload.Subject) != strings.ToLower(subject) {
			return nil, errors.Errorf("token subject '%s' and CSR CommonName '%s' do not match", jwt.Payload.Subject, subject)
		}
	}

	// Prepare client for bootstrap or provisioning tokens
	var options []ca.ClientOption
	if len(jwt.Payload.SHA) > 0 && len(jwt.Payload.Audience) > 0 && strings.HasPrefix(strings.ToLower(jwt.Payload.Audience[0]), "http") {
		if len(caURL) == 0 {
			caURL = jwt.Payload.Audience[0]
		}
		options = append(options, ca.WithRootSHA256(jwt.Payload.SHA))
	} else {
		if len(caURL) == 0 {
			return nil, errs.RequiredFlag(ctx, "ca-url")
		}
		if len(root) == 0 {
			root = pki.GetRootCAPath()
			if _, err := os.Stat(root); err != nil {
				return nil, errs.RequiredFlag(ctx, "root")
			}
		}
		options = append(options, ca.WithRootFile(root))
	}

	ui.PrintSelected("CA", caURL)
	return ca.NewClient(caURL, options...)
}

// GenerateToken generates a token for immediate use (therefore only default
// validity values will be used). The token is generated either with the offline
// token flow or the online mode.
func (f *certificateFlow) GenerateToken(ctx *cli.Context, subject string, sans []string) (string, error) {
	if f.offline {
		return f.offlineCA.GenerateToken(ctx, signType, subject, sans, time.Time{}, time.Time{})
	}

	// Use online CA to get the provisioners and generate the token
	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return "", errs.RequiredUnlessFlag(ctx, "ca-url", "token")
	}

	root := ctx.String("root")
	if len(root) == 0 {
		root = pki.GetRootCAPath()
		if _, err := os.Stat(root); err != nil {
			return "", errs.RequiredUnlessFlag(ctx, "root", "token")
		}
	}

	var err error
	if subject == "" {
		subject, err = ui.Prompt("What DNS names or IP addresses would you like to use? (e.g. internal.smallstep.com)", ui.WithValidateNotEmpty())
		if err != nil {
			return "", err
		}
	}

	return newTokenFlow(ctx, signType, subject, sans, caURL, root, time.Time{}, time.Time{})
}

// Sign signs the CSR using the online or the offline certificate authority.
func (f *certificateFlow) Sign(ctx *cli.Context, token string, csr api.CertificateRequest, crtFile string) error {
	client, err := f.getClient(ctx, csr.Subject.CommonName, token)
	if err != nil {
		return err
	}

	// parse times or durations
	notBefore, notAfter, err := parseTimeDuration(ctx)
	if err != nil {
		return err
	}

	req := &api.SignRequest{
		CsrPEM:    csr,
		OTT:       token,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	resp, err := client.Sign(req)
	if err != nil {
		return err
	}

	serverBlock, err := pemutil.Serialize(resp.ServerPEM.Certificate)
	if err != nil {
		return err
	}
	caBlock, err := pemutil.Serialize(resp.CaPEM.Certificate)
	if err != nil {
		return err
	}
	data := append(pem.EncodeToMemory(serverBlock), pem.EncodeToMemory(caBlock)...)
	return utils.WriteFile(crtFile, data, 0600)
}

// CreateSignRequest is a helper function that given an x509 OTT returns a
// simple but secure sign request as well as the private key used.
func (f *certificateFlow) CreateSignRequest(tok, subject string, sans []string) (*api.SignRequest, crypto.PrivateKey, error) {
	jwt, err := token.ParseInsecure(tok)
	if err != nil {
		return nil, nil, err
	}

	pk, err := keys.GenerateDefaultKey()
	if err != nil {
		return nil, nil, err
	}

	var emails []string
	dnsNames, ips := splitSANs(sans, jwt.Payload.SANs)
	if jwt.Payload.Email != "" {
		emails = append(emails, jwt.Payload.Email)
	}

	switch jwt.Payload.Type() {
	case token.AWS:
		doc := jwt.Payload.Amazon.InstanceIdentityDocument
		if len(ips) == 0 && len(dnsNames) == 0 {
			defaultSANs := []string{
				doc.PrivateIP,
				fmt.Sprintf("ip-%s.%s.compute.internal", strings.Replace(doc.PrivateIP, ".", "-", -1), doc.Region),
			}
			if !sharedContext.DisableCustomSANs {
				defaultSANs = append(defaultSANs, subject)
			}
			dnsNames, ips = splitSANs(defaultSANs)
		}
	case token.GCP:
		ce := jwt.Payload.Google.ComputeEngine
		if len(ips) == 0 && len(dnsNames) == 0 {
			defaultSANs := []string{
				fmt.Sprintf("%s.c.%s.internal", ce.InstanceName, ce.ProjectID),
				fmt.Sprintf("%s.%s.c.%s.internal", ce.InstanceName, ce.Zone, ce.ProjectID),
			}
			if !sharedContext.DisableCustomSANs {
				defaultSANs = append(defaultSANs, subject)
			}
			dnsNames, ips = splitSANs(defaultSANs)
		}
	case token.Azure:
		if len(ips) == 0 && len(dnsNames) == 0 {
			defaultSANs := []string{
				jwt.Payload.Azure.VirtualMachine,
			}
			if !sharedContext.DisableCustomSANs {
				defaultSANs = append(defaultSANs, subject)
			}
			dnsNames, ips = splitSANs(defaultSANs)
		}
	default: // Use common name in the token
		subject = jwt.Payload.Subject
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subject,
		},
		SignatureAlgorithm: keys.DefaultSignatureAlgorithm,
		DNSNames:           dnsNames,
		IPAddresses:        ips,
		EmailAddresses:     emails,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error creating certificate request")
	}
	cr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error parsing certificate request")
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, nil, errors.Wrap(err, "error signing certificate request")
	}
	return &api.SignRequest{
		CsrPEM: api.CertificateRequest{CertificateRequest: cr},
		OTT:    tok,
	}, pk, nil
}

// splitSANs unifies the SAN collections passed as arguments and returns a list
// of DNS names and a list of IP addresses.
func splitSANs(args ...[]string) (dnsNames []string, ipAddresses []net.IP) {
	m := make(map[string]bool)
	var unique []string
	for _, sans := range args {
		for _, san := range sans {
			if ok := m[san]; !ok {
				m[san] = true
				unique = append(unique, san)
			}
		}
	}
	return x509util.SplitSANs(unique)
}

// parseTimeDuration parses the not-before and not-after flags as a timeDuration
func parseTimeDuration(ctx *cli.Context) (notBefore api.TimeDuration, notAfter api.TimeDuration, err error) {
	var zero api.TimeDuration
	notBefore, err = api.ParseTimeDuration(ctx.String("not-before"))
	if err != nil {
		return zero, zero, errs.InvalidFlagValue(ctx, "not-before", ctx.String("not-before"), "")
	}
	notAfter, err = api.ParseTimeDuration(ctx.String("not-after"))
	if err != nil {
		return zero, zero, errs.InvalidFlagValue(ctx, "not-after", ctx.String("not-after"), "")
	}
	return
}

func startHTTPServer(addr string, token string, keyAuth string) *http.Server {
	srv := &http.Server{Addr: addr}

	http.HandleFunc(fmt.Sprintf("/.well-known/acme-challenge/%s", token), func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(keyAuth))
	})

	go func() {
		// returns ErrServerClosed on graceful close
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// NOTE: there is a chance that next line won't have time to run,
			// as main() doesn't wait for this goroutine to stop. don't use
			// code with race conditions like these for production. see post
			// comments below on more discussion on how to handle this.
			ui.Printf("\nListenAndServe(): %s\n", err)
		}
	}()

	// returning reference so caller can call Shutdown()
	return srv
}

type issueMode interface {
	Run() error
	Cleanup() error
}

type standaloneMode struct {
	identifier, token string
	key               *jose.JSONWebKey
	port              int
	srv               *http.Server
}

func newStandaloneMode(identifier string, port int, token string, key *jose.JSONWebKey) *standaloneMode {
	return &standaloneMode{
		identifier: identifier,
		port:       port,
		token:      token,
		key:        key,
	}
}

func (sm *standaloneMode) Run() error {
	ui.Printf("Using Standalone Mode HTTP challenge to validate %s .", sm.identifier)
	keyAuth, err := acme.KeyAuthorization(sm.token, sm.key)
	if err != nil {
		return errors.Wrap(err, "error generating ACME key authorization")
	}
	sm.srv = startHTTPServer(fmt.Sprintf("0.0.0.0:%d", sm.port), sm.token, keyAuth)
	return nil
}

func (sm *standaloneMode) Cleanup() error {
	return errors.Wrap(sm.srv.Shutdown(context.TODO()), "error gracefully shutting down server")
}

type webrootMode struct {
	dir, token, identifier string
	key                    *jose.JSONWebKey
}

func newWebrootMode(dir, token, identifier string, key *jose.JSONWebKey) *webrootMode {
	return &webrootMode{
		dir:        dir,
		token:      token,
		identifier: identifier,
		key:        key,
	}
}

func (wm *webrootMode) Run() error {
	ui.Printf("Using Webroot Mode HTTP challenge to validate %s .", wm.identifier)
	keyAuth, err := acme.KeyAuthorization(wm.token, wm.key)
	if err != nil {
		return errors.Wrap(err, "error generating ACME key authorization")
	}
	_, err = os.Stat(wm.dir)
	switch {
	case os.IsNotExist(err):
		return errors.Errorf("webroot directory %s does not exist", wm.dir)
	case err != nil:
		return errors.Wrapf(err, "error checking for directory %s", wm.dir)
	}

	chPath := fmt.Sprintf("%s/.well-known/acme-challenge", wm.dir)
	if _, err = os.Stat(chPath); os.IsNotExist(err) {
		if err = os.MkdirAll(chPath, 0700); err != nil {
			return errors.Wrapf(err, "error creating directory path %s", chPath)
		}
	}

	return errors.Wrapf(ioutil.WriteFile(fmt.Sprintf("%s/%s", chPath, wm.token), []byte(keyAuth), 0600),
		"error writing key authorization file %s", chPath+wm.token)
}

func (wm *webrootMode) Cleanup() error {
	return errors.Wrap(os.Remove(fmt.Sprintf("%s/.well-known/acme-challenge/%s",
		wm.dir, wm.token)), "error removing ACME challenge file")
}

func serveAndValidateHTTPChallenge(ctx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string) error {
	isStandalone, webroot := ctx.Bool("standalone"), ctx.String("webroot")
	var mode issueMode
	switch {
	case isStandalone && len(webroot) > 0:
		return errs.MutuallyExclusiveFlags(ctx, "standalone", "webroot")
	case !isStandalone && len(webroot) == 0:
		return errs.RequiredWithOrFlag(ctx, "acme", "standalone", "webroot")
	case isStandalone:
		mode = newStandaloneMode(identifier, ctx.Int("http-port"), ch.Token, ac.Key)
	default:
		mode = newWebrootMode(webroot, ch.Token, identifier, ac.Key)
	}
	if err := mode.Run(); err != nil {
		ui.Printf(" Error!\n\n")
		mode.Cleanup()
		return err
	}

	time.Sleep(1 * time.Second)
	if err := ac.ValidateChallenge(ch.URL); err != nil {
		ui.Printf(" Error!\n\n")
		mode.Cleanup()
		return errors.Wrapf(err, "error validating ACME Challenge at %s", ch.URL)
	}
	var (
		isValid = false
		vch     *acme.Challenge
		err     error
	)
	for attempts := 0; attempts < 10; attempts++ {
		time.Sleep(1 * time.Second)
		ui.Printf(".")
		vch, err = ac.GetChallenge(ch.URL)
		if err != nil {
			ui.Printf(" Error!\n\n")
			mode.Cleanup()
			return errors.Wrapf(err, "error retrieving ACME Challenge at %s", ch.URL)
		}
		if vch.Status == "valid" {
			isValid = true
			break
		}
	}
	if !isValid {
		ui.Printf(" Error!\n\n")
		mode.Cleanup()
		return errors.Errorf("Unable to validate challenge: %+v", vch)
	}
	if err := mode.Cleanup(); err != nil {
		return err
	}
	ui.Printf(" done!\n")
	return nil
}

func authorizeOrder(ctx *cli.Context, ac *ca.ACMEClient, o *acme.Order) error {
	for _, azURL := range o.Authorizations {
		az, err := ac.GetAuthz(azURL)
		if err != nil {
			return errors.Wrapf(err, "error retrieving ACME Authz at %s", azURL)
		}

		ident := az.Identifier.Value
		if az.Wildcard {
			ident = "*." + ident
		}

		chValidated := false
		for _, ch := range az.Challenges {
			// TODO: Allow other types of challenges (not just http).
			if ch.Type == "http-01" {
				if err := serveAndValidateHTTPChallenge(ctx, ac, ch, ident); err != nil {
					return err
				}
				chValidated = true
				break
			}
		}
		if !chValidated {
			if az.Wildcard {
				return errors.Errorf("wildcard dnsnames (%s) require dns validation, "+
					"which is currently not implemented in this client", ident)
			}
			return errors.Errorf("unable to validate any challenges for identifier: %s", ident)
		}
	}
	return nil
}

func finalizeOrder(ac *ca.ACMEClient, o *acme.Order, csr *x509.CertificateRequest) (*acme.Order, error) {
	var (
		err              error
		ro, fo           *acme.Order
		isReady, isValid bool
	)
	ui.Printf("Waiting for Order to be 'ready' for finalization .")
	for i := 9; i >= 0; i-- {
		time.Sleep(1 * time.Second)
		ui.Printf(".")
		ro, err = ac.GetOrder(o.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "error retrieving order %s", o.ID)
		}
		if ro.Status == "ready" {
			isReady = true
			ui.Printf(" done!\n")
			break
		}
	}
	if !isReady {
		ui.Printf(" Error!\n\n")
		return nil, errors.Errorf("Unable to validate order: %+v", ro)
	}

	ui.Printf("Finalizing Order .")
	if err = ac.FinalizeOrder(o.Finalize, csr); err != nil {
		return nil, errors.Wrapf(err, "error finalizing order")
	}

	for i := 9; i >= 0; i-- {
		time.Sleep(1 * time.Second)
		ui.Printf(".")
		fo, err = ac.GetOrder(o.ID)
		if err != nil {
			return nil, errors.Wrapf(err, "error retrieving order %s", o.ID)
		}
		if fo.Status == "valid" {
			isValid = true
			ui.Printf(" done!\n")
			break
		}
	}
	if !isValid {
		ui.Printf(" Error!\n\n")
		return nil, errors.Errorf("Unable to finalize order: %+v", fo)
	}

	return fo, nil
}

func acmeFlow(ctx *cli.Context) error {
	args := ctx.Args()
	subject := args.Get(0)
	crtFile, keyFile := args.Get(1), args.Get(2)

	sans := ctx.StringSlice("san")

	if len(sans) == 0 {
		sans = []string{subject}
	}
	dnsNames, ips := splitSANs(sans)
	if len(ips) > 0 {
		return errors.New("IP Address SANs are not supported for ACME flow")
	}

	caURL := ctx.String("ca-url")
	if len(caURL) == 0 {
		return errs.RequiredFlag(ctx, "ca-url")
	}
	if !(strings.HasSuffix(caURL, "directory") || strings.HasSuffix(caURL, "dir")) {
		caURL = caURL + "/acme/directory"
	}

	var idents []acme.Identifier
	for _, dns := range dnsNames {
		idents = append(idents, acme.Identifier{
			Type:  "dns",
			Value: dns,
		})
	}

	var (
		err          error
		orderPayload []byte
		clientOps    []ca.ClientOption
	)
	if strings.Contains(caURL, "letsencrypt") {
		// LetsEncrypt does not support NotBefore and NotAfter attributes in orders.
		if ctx.IsSet("not-before") || ctx.IsSet("not-after") {
			return errors.New("LetsEncrypt public CA does not support NotBefore/NotAfter " +
				"attributes for certificates. Instead, each certificate has a default lifetime of 3 months.")
		}
		// Use default transport for public CAs
		clientOps = append(clientOps, ca.WithTransport(http.DefaultTransport))
		// LetsEncrypt requires that the Common Name of the Certificate also be
		// represented as a DNSName in the SAN extension, and therefore must be
		// authorized as part of the ACME order.
		hasSubject := false
		for _, n := range idents {
			if n.Value == subject {
				hasSubject = true
			}
		}
		if !hasSubject {
			dnsNames = append(dnsNames, subject)
			idents = append(idents, acme.Identifier{
				Type:  "dns",
				Value: subject,
			})
		}
		orderPayload, err = json.Marshal(struct {
			Identifiers []acme.Identifier
		}{Identifiers: idents})
		if err != nil {
			return errors.Wrap(err, "error marshaling new letsencrypt order request")
		}
	} else {
		// If the CA is not public then a root file is required.
		root := ctx.String("root")
		if len(root) == 0 {
			return errs.RequiredFlag(ctx, "root")
		}
		clientOps = append(clientOps, ca.WithRootFile(root))
		// parse times or durations
		nbf, naf, err := parseTimeDuration(ctx)
		if err != nil {
			return err
		}

		nor := acmeAPI.NewOrderRequest{
			Identifiers: idents,
			NotAfter:    naf.Time(),
			NotBefore:   nbf.Time(),
		}
		orderPayload, err = json.Marshal(nor)
		if err != nil {
			return errors.Wrap(err, "error marshaling new order request")
		}
	}

	ac, err := ca.NewACMEClient(caURL, ctx.StringSlice("contact"), clientOps...)
	if err != nil {
		return errors.Wrapf(err, "error initializing ACME client with server %s", caURL)
	}

	o, err := ac.NewOrder(orderPayload)
	if err != nil {
		return errors.Wrapf(err, "error creating new ACME order")
	}

	if err := authorizeOrder(ctx, ac, o); err != nil {
		return err
	}

	kty, crv, size, err := utils.GetKeyDetailsFromCLI(ctx, ctx.Bool("insecure"), "kty", "curve", "size")
	if err != nil {
		return err
	}
	priv, err := keys.GenerateKey(kty, crv, size)
	if err != nil {
		return errors.Wrap(err, "error generating private key")
	}

	_csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subject,
		},
		DNSNames: dnsNames,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, _csr, priv)
	if err != nil {
		return errors.Wrap(err, "error creating certificate request")
	}
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return errors.Wrap(err, "error parsing certificate request")
	}

	fo, err := finalizeOrder(ac, o, csr)
	if err != nil {
		return err
	}

	leaf, chain, err := ac.GetCertificate(fo.Certificate)
	if err != nil {
		return errors.Wrapf(err, "error getting certificate")
	}

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leaf.Raw,
	})
	for _, cert := range chain {
		certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	if err := utils.WriteFile(crtFile, certBytes, 0600); err != nil {
		return errs.FileError(err, crtFile)
	}

	_, err = pemutil.Serialize(priv, pemutil.ToFile(keyFile, 0600))
	if err != nil {
		return errors.WithStack(err)
	}

	ui.PrintSelected("Certificate", crtFile)
	ui.PrintSelected("Private Key", keyFile)
	return nil
}
