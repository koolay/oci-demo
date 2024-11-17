// Package main provides functionality for working with OCI artifacts
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/google/go-containerregistry/pkg/name"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Constants for configuration
const (
	defaultTimeout              = 30 * time.Minute
	defaultRetrySteps           = 10
	defaultRetryInitialDuration = 1 * time.Second
	defaultRetryFactor          = 3
	defaultRetryJitter          = 0.1
)

// OCI specific constants
const (
	OCIRepositoryPrefix = "oci://"
	SourceAnnotation    = "org.opencontainers.image.source"
	RevisionAnnotation  = "org.opencontainers.image.revision"
	CreatedAnnotation   = "org.opencontainers.image.created"
)

// Media type constants
var (
	CanonicalConfigMediaType  = types.MediaType("application/vnd.cncf.artifact.config.v1+json")
	CanonicalMediaTypePrefix  = types.MediaType("application/vnd.cncf.artifact.content.v1")
	CanonicalContentMediaType = types.MediaType(
		fmt.Sprintf("%s.tar+gzip", CanonicalMediaTypePrefix),
	)
)

// LayerType defines the type of layer to be created
type LayerType string

const (
	LayerTypeTarball LayerType = "tarball"
	LayerTypeStatic  LayerType = "static"
)

// Client handles OCI artifact operations
type Client struct {
	options []crane.Option
	timeout time.Duration
}

// NewClient creates a new Client with default settings
func NewClient(opts ...crane.Option) *Client {
	return &Client{
		options: opts,
		timeout: defaultTimeout,
	}
}

// Config represents client configuration
type Config struct {
	Timeout     time.Duration
	RetryConfig RetryConfig
}

// RetryConfig contains retry-related settings
type RetryConfig struct {
	Enabled     bool
	MaxRetries  int
	InitialWait time.Duration
	MaxWait     time.Duration
}

// Metadata contains artifact metadata
type Metadata struct {
	Created     string            `json:"created,omitempty"`
	Source      string            `json:"source_url,omitempty"`
	Revision    string            `json:"source_revision,omitempty"`
	Digest      string            `json:"digest"`
	URL         string            `json:"url"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ToAnnotations converts metadata to OCI annotations
func (m *Metadata) ToAnnotations() map[string]string {
	annotations := map[string]string{
		CreatedAnnotation:  m.Created,
		SourceAnnotation:   m.Source,
		RevisionAnnotation: m.Revision,
	}

	for k, v := range m.Annotations {
		annotations[k] = v
	}

	return annotations
}

// PushOptions configures the push operation
type PushOptions struct {
	layerType LayerType
	layerOpts layerOptions
	meta      Metadata
}

type layerOptions struct {
	mediaTypeExt string
}

// PushOption is a function for configuring PushOptions
type PushOption func(o *PushOptions)

// WithLayerType sets the layer type
func WithLayerType(lt LayerType) PushOption {
	return func(o *PushOptions) {
		o.layerType = lt
	}
}

// WithMediaTypeExtension sets the media type extension
func WithMediaTypeExtension(ext string) PushOption {
	return func(o *PushOptions) {
		o.layerOpts.mediaTypeExt = ext
	}
}

// WithMetadata sets the metadata
func WithMetadata(meta Metadata) PushOption {
	return func(o *PushOptions) {
		o.meta = meta
	}
}

// PushLayer pushes a layer to an OCI registry, returns the digest of the layer
// skip if the layer already exists in the image
// sourcePath is the path to the layer file
// ociURL is the OCI URL of the registry
// opts are PushOptions
func (c *Client) PushLayer(
	ctx context.Context,
	sourcePath, ociURL string,
	opts ...PushOption,
) (string, error) {
	if err := c.validateInputs(sourcePath, ociURL); err != nil {
		return "", fmt.Errorf("invalid inputs: %w", err)
	}

	ref, auth, err := c.setupPush(ctx, ociURL)
	if err != nil {
		return "", err
	}

	pushOpts := c.configurePushOptions(opts)
	img, err := c.setupImage(ctx, ref, pushOpts.meta)
	if err != nil {
		return "", err
	}

	newlayer, err := c.createLayer(sourcePath, pushOpts.layerType, pushOpts.layerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create layer: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return "", fmt.Errorf("failed to get layers: %w", err)
	}

	// check if the layer already exists in the image, if so, skip it
	for _, layer := range layers {
		hash, err := layer.Digest()
		if err != nil {
			return "", fmt.Errorf("failed to get layer digest: %w", err)
		}
		newHash, err := newlayer.Digest()
		if err != nil {
			return "", fmt.Errorf("failed to get new layer digest: %w", err)
		}

		if hash == newHash {
			return c.getDigest(img, ref)
		}
	}

	img, err = c.appendLayer(img, newlayer)
	if err != nil {
		return "", err
	}

	if err := c.pushImage(ctx, img, ref, auth); err != nil {
		return "", err
	}

	return c.getDigest(img, ref)
}

// Helper functions

func (c *Client) validateInputs(sourcePath, ociURL string) error {
	if sourcePath == "" {
		return errors.New("source path cannot be empty")
	}
	if ociURL == "" {
		return errors.New("OCI URL cannot be empty")
	}
	return nil
}

func (c *Client) setupPush(
	ctx context.Context,
	ociURL string,
) (name.Reference, authn.Authenticator, error) {
	url, err := c.ParseArtifactURL(ociURL)
	if err != nil {
		return nil, nil, err
	}

	ref, err := name.ParseReference(url)
	if err != nil {
		return nil, nil, err
	}

	auth, err := c.getAuth(ref)
	if err != nil {
		return nil, nil, err
	}

	return ref, auth, nil
}

func (c *Client) configurePushOptions(opts []PushOption) *PushOptions {
	pushOpts := &PushOptions{
		layerType: LayerTypeTarball,
	}
	for _, opt := range opts {
		opt(pushOpts)
	}
	return pushOpts
}

func (c *Client) createLayer(
	sourcePath string,
	layerType LayerType,
	opts layerOptions,
) (gcrv1.Layer, error) {
	switch layerType {
	case LayerTypeTarball:
		return tarball.LayerFromFile(
			sourcePath,
			tarball.WithMediaType(CanonicalContentMediaType),
			tarball.WithCompressedCaching,
		)
	case LayerTypeStatic:
		content, err := os.ReadFile(sourcePath)
		if err != nil {
			return nil, fmt.Errorf("error reading file for static layer: %w", err)
		}
		return static.NewLayer(content, getLayerMediaType(opts.mediaTypeExt)), nil
	default:
		return nil, fmt.Errorf("unsupported layer type: %s", layerType)
	}
}

func (c *Client) setupImage(
	ctx context.Context,
	ref name.Reference,
	meta Metadata,
) (gcrv1.Image, error) {
	refstr := ref.String()
	img, err := crane.Pull(refstr, c.optionsWithContext(ctx)...)
	if err != nil {
		// if the error is a manifest unknown error, then we need to create a manifest
		if strings.Contains(err.Error(), string(transport.ManifestUnknownErrorCode)) {
			img = mutate.MediaType(empty.Image, types.OCIManifestSchema1)
			img = mutate.ConfigMediaType(img, CanonicalConfigMediaType)
			img = mutate.Annotations(img, meta.ToAnnotations()).(gcrv1.Image)
		} else {
			return nil, fmt.Errorf("failed to pull image: %w, ref: %s", err, refstr)
		}
	}
	return img, nil
}

func (c *Client) appendLayer(img gcrv1.Image, layer gcrv1.Layer) (gcrv1.Image, error) {
	return mutate.Append(img, mutate.Addendum{Layer: layer})
}

func (c *Client) pushImage(
	ctx context.Context,
	img gcrv1.Image,
	ref name.Reference,
	auth authn.Authenticator,
) error {
	backoff := remote.Backoff{
		Duration: defaultRetryInitialDuration,
		Factor:   defaultRetryFactor,
		Jitter:   defaultRetryJitter,
		Steps:    defaultRetrySteps,
		Cap:      c.timeout,
	}

	transportOpts, err := c.WithRetryTransport(
		ctx,
		ref,
		auth,
		backoff,
		[]string{ref.Context().Scope(transport.PushScope)},
	)
	if err != nil {
		return fmt.Errorf("error setting up transport: %w", err)
	}

	c.options = append(c.options, transportOpts, WithRetryBackOff(backoff))

	return crane.Push(img, ref.String(), c.optionsWithContext(ctx)...)
}

func (c *Client) getDigest(img gcrv1.Image, ref name.Reference) (string, error) {
	digest, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("parsing artifact digest failed: %w", err)
	}
	return ref.Context().Digest(digest.String()).String(), nil
}

// Utility functions

func getLayerMediaType(extension string) types.MediaType {
	if extension == "" {
		return CanonicalMediaTypePrefix
	}
	return types.MediaType(fmt.Sprintf("%s.%s", CanonicalMediaTypePrefix, extension))
}

func (c *Client) ParseArtifactURL(ociURL string) (string, error) {
	if !strings.HasPrefix(ociURL, OCIRepositoryPrefix) {
		return "", errors.New("URL must be in format 'oci://<domain>/<org>/<repo>'")
	}

	url := strings.TrimPrefix(ociURL, OCIRepositoryPrefix)
	if _, err := name.ParseReference(url); err != nil {
		return "", fmt.Errorf("invalid URL %s: %w", ociURL, err)
	}

	return url, nil
}

// Authentication related functions

func (c *Client) getAuth(ref name.Reference) (authn.Authenticator, error) {
	if creds := os.Getenv("OCI_CREDS"); creds != "" {
		return c.GetAuthFromCredentials(creds)
	}
	return authn.DefaultKeychain.Resolve(ref.Context())
}

func (c *Client) GetAuthFromCredentials(credentials string) (authn.Authenticator, error) {
	if credentials == "" {
		return nil, errors.New("credentials cannot be empty")
	}

	parts := strings.SplitN(credentials, ":", 2)
	var authConfig authn.AuthConfig

	if len(parts) == 1 {
		authConfig = authn.AuthConfig{RegistryToken: parts[0]}
	} else {
		authConfig = authn.AuthConfig{Username: parts[0], Password: parts[1]}
	}

	return authn.FromConfig(authConfig), nil
}

// Transport related functions

func (c *Client) WithRetryTransport(
	ctx context.Context,
	ref name.Reference,
	auth authn.Authenticator,
	backoff remote.Backoff,
	scopes []string,
) (crane.Option, error) {
	var retryTransport http.RoundTripper
	retryTransport = remote.DefaultTransport.(*http.Transport).Clone()
	if logs.Enabled(logs.Debug) {
		retryTransport = transport.NewLogger(retryTransport)
	}

	retryTransport = transport.NewRetry(retryTransport,
		transport.WithRetryPredicate(defaultRetryPredicate),
		transport.WithRetryStatusCodes(retryableStatusCodes...),
		transport.WithRetryBackoff(backoff))

	t, err := transport.NewWithContext(ctx, ref.Context().Registry, auth, retryTransport, scopes)
	if err != nil {
		return nil, err
	}
	return crane.WithTransport(t), nil
}

func WithRetryBackOff(backoff remote.Backoff) crane.Option {
	return func(options *crane.Options) {
		options.Remote = append(options.Remote, remote.WithRetryBackoff(backoff))
	}
}

func (c *Client) optionsWithContext(ctx context.Context) []crane.Option {
	return append([]crane.Option{crane.WithContext(ctx)}, c.options...)
}

var defaultRetryPredicate = func(err error) bool {
	if isTemporary(err) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) {
		logs.Warn.Printf("retrying %v", err)
		return true
	}
	return false
}

var retryableStatusCodes = []int{
	http.StatusRequestTimeout,
	http.StatusInternalServerError,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
}

func isTemporary(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if te, ok := err.(interface{ Temporary() bool }); ok && te.Temporary() {
		return true
	}
	return false
}
