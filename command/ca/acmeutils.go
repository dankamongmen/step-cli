package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	acmeAPI "github.com/smallstep/certificates/acme/api"
	"github.com/smallstep/certificates/ca"
	"github.com/smallstep/cli/crypto/keys"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/pki"
	"github.com/smallstep/cli/errs"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/cli/ui"
	"github.com/smallstep/cli/utils"
	"github.com/urfave/cli"
)

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
	listenAddr        string
	srv               *http.Server
}

func newStandaloneMode(identifier, listenAddr, token string, key *jose.JSONWebKey) *standaloneMode {
	return &standaloneMode{
		identifier: identifier,
		listenAddr: listenAddr,
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
	sm.srv = startHTTPServer(sm.listenAddr, sm.token, keyAuth)
	return nil
}

func (sm *standaloneMode) Cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	return errors.Wrap(sm.srv.Shutdown(ctx), "error gracefully shutting down server")
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

	// Use 0755 and 0644 (rather than 0700 and 0600) for directory and file
	// respectively because the process running the file server, and therefore
	// reading/serving the file, may be owned by a different user than
	// the one running the `step` command that will write the file.
	chPath := fmt.Sprintf("%s/.well-known/acme-challenge", wm.dir)
	if _, err = os.Stat(chPath); os.IsNotExist(err) {
		if err = os.MkdirAll(chPath, 0755); err != nil {
			return errors.Wrapf(err, "error creating directory path %s", chPath)
		}
	}

	return errors.Wrapf(ioutil.WriteFile(fmt.Sprintf("%s/%s", chPath, wm.token), []byte(keyAuth), 0644),
		"error writing key authorization file %s", chPath+wm.token)
}

func (wm *webrootMode) Cleanup() error {
	return errors.Wrap(os.Remove(fmt.Sprintf("%s/.well-known/acme-challenge/%s",
		wm.dir, wm.token)), "error removing ACME challenge file")
}

func serveAndValidateHTTPChallenge(ctx *cli.Context, ac *ca.ACMEClient, ch *acme.Challenge, identifier string) error {
	var mode issueMode
	if ctx.Bool("standalone") {
		mode = newStandaloneMode(identifier, ctx.String("http-listen"), ch.Token, ac.Key)
	} else {
		mode = newWebrootMode(ctx.String("webroot"), ch.Token, identifier, ac.Key)
	}
	if err := mode.Run(); err != nil {
		ui.Printf(" Error!\n\n")
		mode.Cleanup()
		return err
	}

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

func validateSANsForACME(sans []string) ([]string, error) {
	dnsNames, ips := splitSANs(sans)
	if len(ips) > 0 {
		return nil, errors.New("IP Address SANs are not supported for ACME flow")
	}
	for _, dns := range dnsNames {
		if strings.Contains(dns, "*") {
			return nil, errors.Errorf("wildcard dnsnames (%s) require dns validation, "+
				"which is currently not implemented in this client", dns)
		}
	}
	return dnsNames, nil
}

func acmeFlow(ctx *cli.Context, provID string) error {
	// Offline mode is not supported for ACME protocol
	if ctx.Bool("offline") {
		return errors.New("offline mode and ACME are mutually exclusive")
	}
	// One of --standalone or --webroot must be selected for use with ACME protocol.
	isStandalone, webroot := ctx.Bool("standalone"), ctx.String("webroot")
	switch {
	case isStandalone && len(webroot) > 0:
		return errs.MutuallyExclusiveFlags(ctx, "standalone", "webroot")
	case !isStandalone && len(webroot) == 0:
		if err := ctx.Set("standalone", "true"); err != nil {
			return errors.Wrap(err, "error setting 'standalone' value in cli ctx")
		}
	}

	args := ctx.Args()
	subject := args.Get(0)
	crtFile, keyFile := args.Get(1), args.Get(2)
	acmeDir := ctx.String("acme")
	if len(acmeDir) == 0 {
		caURL := ctx.String("ca-url")
		if len(caURL) == 0 {
			return errs.RequiredFlag(ctx, "ca-url")
		}
		acmeDir = fmt.Sprintf("%s/acme/%s/directory", caURL, provID)
	}

	sans := ctx.StringSlice("san")
	if len(sans) == 0 {
		sans = []string{subject}
	}

	dnsNames, err := validateSANsForACME(sans)
	if err != nil {
		return err
	}

	var idents []acme.Identifier
	for _, dns := range dnsNames {
		idents = append(idents, acme.Identifier{
			Type:  "dns",
			Value: dns,
		})
	}

	var (
		orderPayload []byte
		clientOps    []ca.ClientOption
	)
	if strings.Contains(acmeDir, "letsencrypt") {
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
			root = pki.GetRootCAPath()
			if _, err := os.Stat(root); err != nil {
				return errs.RequiredFlag(ctx, "root")
			}
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

	ac, err := ca.NewACMEClient(acmeDir, ctx.StringSlice("contact"), clientOps...)
	if err != nil {
		return errors.Wrapf(err, "error initializing ACME client with server %s", acmeDir)
	}

	o, err := ac.NewOrder(orderPayload)
	if err != nil {
		return errors.Wrapf(err, "error creating new ACME order")
	}

	if err := authorizeOrder(ctx, ac, o); err != nil {
		return err
	}

	priv, err := keys.GenerateDefaultKey()
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
