// Command jacsgo-install installs the version-matched JACS native library into
// a vendored jacsgo module. The Go bindings intentionally link from
// ${SRCDIR}/build, so the installer writes only that directory after verifying
// the release checksum.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

const (
	modulePath           = "github.com/HumanAssisted/JACS/jacsgo"
	defaultReleaseBase   = "https://github.com/HumanAssisted/JACS/releases/download"
	maxChecksumFileSize  = 1 << 20
	maxNativeLibrarySize = 128 << 20
)

var semanticVersion = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)

type installOptions struct {
	Version     string
	GOOS        string
	GOARCH      string
	ModuleDir   string
	ReleaseBase string
	Client      *http.Client
}

func main() {
	versionFlag := flag.String("version", "", "semantic jacsgo version to install (for example v0.11.4)")
	moduleDirFlag := flag.String("module-dir", "", "jacsgo module directory (default: current module's vendored jacsgo directory)")
	timeoutFlag := flag.Duration("timeout", 60*time.Second, "total download timeout")
	flag.Parse()

	version, err := requestedVersion(*versionFlag)
	if err != nil {
		fatal(err)
	}

	moduleDir := *moduleDirFlag
	if moduleDir == "" {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			fatal(fmt.Errorf("determine working directory: %w", cwdErr))
		}
		root, rootErr := findModuleRoot(cwd)
		if rootErr != nil {
			fatal(rootErr)
		}
		moduleDir, err = defaultVendorModuleDir(root, version)
		if err != nil {
			fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()
	client := &http.Client{
		Timeout: *timeoutFlag,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many release download redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("release download redirected to a non-HTTPS URL")
			}
			return nil
		},
	}
	if err := installNative(ctx, installOptions{
		Version:     version,
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		ModuleDir:   moduleDir,
		ReleaseBase: defaultReleaseBase,
		Client:      client,
	}); err != nil {
		fatal(err)
	}

	_, libraryName, _ := releaseAsset(version, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("installed checksum-verified %s to %s\n", libraryName, filepath.Join(moduleDir, "build"))
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "jacsgo-install: %v\n", err)
	os.Exit(1)
}

func requestedVersion(explicit string) (string, error) {
	version := strings.TrimSpace(explicit)
	if version == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Path == modulePath+"/cmd/jacsgo-install" || strings.HasPrefix(info.Main.Path, modulePath) {
				version = info.Main.Version
			}
			if version == "" || version == "(devel)" {
				for _, dep := range info.Deps {
					if dep.Path == modulePath {
						version = dep.Version
						break
					}
				}
			}
		}
	}
	if version != "" && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if !semanticVersion.MatchString(version) {
		return "", fmt.Errorf("a semantic -version such as v0.11.4 is required (got %q)", version)
	}
	return version, nil
}

func releaseAsset(version, goos, goarch string) (assetName, libraryName string, err error) {
	if !semanticVersion.MatchString(version) {
		return "", "", fmt.Errorf("invalid semantic version %q", version)
	}
	switch goos + "/" + goarch {
	case "darwin/amd64", "darwin/arm64":
		return fmt.Sprintf("jacsgo-%s-%s-%s.dylib", version, goos, goarch), "libjacsgo.dylib", nil
	case "linux/amd64", "linux/arm64":
		return fmt.Sprintf("jacsgo-%s-%s-%s.so", version, goos, goarch), "libjacsgo.so", nil
	default:
		return "", "", fmt.Errorf("no prebuilt jacsgo native library for %s/%s", goos, goarch)
	}
}

func checksumFor(manifest []byte, assetName string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(manifest)))
	var found string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return "", fmt.Errorf("malformed checksum manifest line for %q", assetName)
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name != assetName {
			continue
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size {
			return "", fmt.Errorf("malformed SHA-256 for %q", assetName)
		}
		if found != "" {
			return "", fmt.Errorf("duplicate checksum entry for %q", assetName)
		}
		found = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read checksum manifest: %w", err)
	}
	if found == "" {
		return "", fmt.Errorf("checksum manifest has no entry for %q", assetName)
	}
	return found, nil
}

func installNative(ctx context.Context, opts installOptions) error {
	assetName, libraryName, err := releaseAsset(opts.Version, opts.GOOS, opts.GOARCH)
	if err != nil {
		return err
	}
	if opts.Client == nil {
		return errors.New("HTTP client is required")
	}
	if opts.ReleaseBase == "" {
		return errors.New("release base URL is required")
	}
	moduleInfo, err := os.Lstat(opts.ModuleDir)
	if err != nil {
		return fmt.Errorf("jacsgo module directory %q is unavailable: %w", opts.ModuleDir, err)
	}
	if !moduleInfo.IsDir() || moduleInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("jacsgo module directory %q must be a real directory", opts.ModuleDir)
	}

	tag := "jacsgo/" + opts.Version
	checksumName := fmt.Sprintf("jacsgo-%s-sha256sums.txt", opts.Version)
	checksumURL, err := releaseDownloadURL(opts.ReleaseBase, tag, checksumName)
	if err != nil {
		return err
	}
	assetURL, err := releaseDownloadURL(opts.ReleaseBase, tag, assetName)
	if err != nil {
		return err
	}
	manifest, err := downloadBounded(ctx, opts.Client, checksumURL, maxChecksumFileSize)
	if err != nil {
		return fmt.Errorf("download checksum manifest: %w", err)
	}
	wantChecksum, err := checksumFor(manifest, assetName)
	if err != nil {
		return err
	}
	payload, err := downloadBounded(ctx, opts.Client, assetURL, maxNativeLibrarySize)
	if err != nil {
		return fmt.Errorf("download native library: %w", err)
	}
	want, _ := hex.DecodeString(wantChecksum)
	gotSum := sha256.Sum256(payload)
	if subtle.ConstantTimeCompare(gotSum[:], want) != 1 {
		return fmt.Errorf("checksum mismatch for %q", assetName)
	}

	buildDir := filepath.Join(opts.ModuleDir, "build")
	if err := ensureRealDirectory(buildDir); err != nil {
		return err
	}
	libraryPath := filepath.Join(buildDir, libraryName)
	if info, statErr := os.Lstat(libraryPath); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to replace symlink at %q", libraryPath)
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect native library destination: %w", statErr)
	}
	if err := writeAtomicExecutable(libraryPath, payload); err != nil {
		return fmt.Errorf("install native library: %w", err)
	}
	return nil
}

func releaseDownloadURL(base, tag, name string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid release base URL %q", base)
	}
	return strings.TrimRight(base, "/") + "/" + url.PathEscape(tag) + "/" + url.PathEscape(name), nil
}

func downloadBounded(ctx context.Context, client *http.Client, location string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "jacsgo-install")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d-byte limit", maxBytes)
	}
	return data, nil
}

func ensureRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o755); err != nil {
			return fmt.Errorf("create native build directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect native build directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("native build path %q must be a real directory", path)
	}
	return nil
}

func writeAtomicExecutable(path string, payload []byte) (retErr error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".jacsgo-native-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if retErr != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o755); err != nil {
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func findModuleRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if info, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil && !info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod found; run the installer from an external Go module")
		}
		dir = parent
	}
}

func defaultVendorModuleDir(moduleRoot, version string) (string, error) {
	vendorDir := filepath.Join(moduleRoot, "vendor")
	modulesPath := filepath.Join(vendorDir, "modules.txt")
	modules, err := os.ReadFile(modulesPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w; run `go mod vendor` first", modulesPath, err)
	}
	wantHeader := "# " + modulePath + " "
	foundVersion := ""
	scanner := bufio.NewScanner(strings.NewReader(string(modules)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, wantHeader) {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				foundVersion = fields[2]
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read vendored module inventory: %w", err)
	}
	if foundVersion == "" {
		return "", fmt.Errorf("%s is not present in vendor/modules.txt; run `go get %s@%s` and `go mod vendor`", modulePath, modulePath, version)
	}
	if foundVersion != version {
		return "", fmt.Errorf("installer version %s does not match vendored %s version %s", version, modulePath, foundVersion)
	}
	moduleDir := filepath.Join(vendorDir, filepath.FromSlash(modulePath))
	info, err := os.Stat(moduleDir)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("vendored jacsgo directory %q is unavailable; run `go mod vendor`", moduleDir)
	}
	return moduleDir, nil
}
