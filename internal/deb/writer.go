package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5" // #nosec G501 -- Debian packages require MD5 file integrity metadata.
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type tarEntry struct {
	name     string
	body     []byte
	mode     int64
	modTime  time.Time
	typeFlag byte
}

func writeArchive(p Package) error {
	dataEntries := make([]tarEntry, 0, len(p.Files))
	var md5sums strings.Builder
	var installedBytes int64
	for _, file := range p.Files {
		entry, err := readPackageFile(file)
		if err != nil {
			return err
		}
		dataEntries = append(dataEntries, entry)
		installedBytes += int64(len(entry.body))
		sum := md5.Sum(entry.body) // #nosec G401 -- Required by Debian's md5sums control file.
		fmt.Fprintf(&md5sums, "%x  %s\n", sum, entry.name)
	}

	now := time.Now()
	dataEntries = append(buildDirectoryEntries(dataEntries, now), dataEntries...)
	dataArchive, err := makeTarGzip(dataEntries)
	if err != nil {
		return fmt.Errorf("create data archive: %w", err)
	}
	controlArchive, err := makeTarGzip(controlEntries(p, md5sums.String(), installedBytes, now))
	if err != nil {
		return fmt.Errorf("create control archive: %w", err)
	}

	members := make([]arMember, 0, 3)
	for _, member := range []struct {
		name string
		body []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", controlArchive},
		{"data.tar.gz", dataArchive},
	} {
		arEntry, err := newArMember(member.name, member.body, now)
		if err != nil {
			return err
		}
		members = append(members, arEntry)
	}
	return writePackageFile(p.Output, writeAr(members))
}

func buildDirectoryEntries(entries []tarEntry, modTime time.Time) []tarEntry {
	directories := make(map[string]struct{})
	for _, entry := range entries {
		for directory := path.Dir(entry.name); directory != "."; directory = path.Dir(directory) {
			directories[directory+"/"] = struct{}{}
		}
	}

	names := make([]string, 0, len(directories))
	for name := range directories {
		names = append(names, name)
	}
	sort.Strings(names)

	directoryEntries := make([]tarEntry, 0, len(names))
	for _, name := range names {
		directoryEntries = append(directoryEntries, tarEntry{
			name:     name,
			mode:     0o755,
			modTime:  modTime,
			typeFlag: tar.TypeDir,
		})
	}
	return directoryEntries
}

// packageFiles returns the DevBox Gateway install manifest. The config file is
// installed 0640 (root read/write, no group or world read) because it can hold
// secrets such as SNI_HASH_SECRET. The data archive owns every entry as
// root:root (uid/gid 0), so 0640 keeps the file readable only by root. The
// other files carry no secrets and use the conventional world-readable modes.
func packageFiles(o Options) ([]File, error) {
	files := []File{
		{Source: o.BinarySource, Destination: o.BinaryDestination, Mode: 0o755},
		{Source: o.UnitSource, Destination: unitDestination, Mode: 0o644},
		{Source: o.ConfigSource, Destination: confDestination, Mode: 0o640, Conffile: true},
	}
	if _, err := os.Stat(o.LicenseSource); err == nil {
		files = append(files, File{Source: o.LicenseSource, Destination: licenseDest, Mode: 0o644})
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat license: %w", err)
	}
	return files, nil
}

func readPackageFile(file File) (tarEntry, error) {
	cleanDestination := filepath.ToSlash(filepath.Clean(file.Destination))
	if !strings.HasPrefix(cleanDestination, "/") || cleanDestination == "/" {
		return tarEntry{}, fmt.Errorf("package destination must be an absolute file path: %q", file.Destination)
	}

	source, err := os.Open(file.Source) //nolint:gosec // Sources are explicitly supplied packaging inputs.
	if err != nil {
		return tarEntry{}, fmt.Errorf("open %s: %w", file.Source, err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return tarEntry{}, fmt.Errorf("stat %s: %w", file.Source, err)
	}
	if !info.Mode().IsRegular() {
		return tarEntry{}, fmt.Errorf("package source is not a regular file: %s", file.Source)
	}
	body, err := io.ReadAll(source)
	if err != nil {
		return tarEntry{}, fmt.Errorf("read %s: %w", file.Source, err)
	}
	return tarEntry{
		name:    strings.TrimPrefix(cleanDestination, "/"),
		body:    body,
		mode:    file.Mode,
		modTime: info.ModTime(),
	}, nil
}

// controlEntries renders control.tar.gz: the control file itself, md5sums, the
// conffiles list, and whichever maintainer scripts p defines.
func controlEntries(p Package, md5sums string, installedBytes int64, now time.Time) []tarEntry {
	installedSize := (installedBytes + 1023) / 1024
	var control strings.Builder
	fmt.Fprintf(&control, "Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: %s\n"+
		"Installed-Size: %d\nSection: %s\nHomepage: %s\n",
		p.Name, p.Version, p.Arch, p.Maintainer, installedSize, p.Section, p.Homepage)
	if p.Depends != "" {
		fmt.Fprintf(&control, "Depends: %s\n", p.Depends)
	}
	fmt.Fprintf(&control, "Description: %s\n %s\n", p.Summary, strings.ReplaceAll(p.Description, "\n", "\n "))

	var conffiles strings.Builder
	for _, file := range p.Files {
		if file.Conffile {
			conffiles.WriteString(filepath.ToSlash(filepath.Clean(file.Destination)) + "\n")
		}
	}

	var entries []tarEntry
	for _, script := range []struct{ name, body string }{
		{"postinst", p.Postinst},
		{"prerm", p.Prerm},
		{"postrm", p.Postrm},
	} {
		if script.body != "" {
			entries = append(entries, tarEntry{name: script.name, body: []byte(script.body), mode: 0o755, modTime: now})
		}
	}
	if conffiles.Len() > 0 {
		entries = append(entries, tarEntry{name: "conffiles", body: []byte(conffiles.String()), mode: 0o644, modTime: now})
	}
	return append(entries,
		tarEntry{name: "control", body: []byte(control.String()), mode: 0o644, modTime: now},
		tarEntry{name: "md5sums", body: []byte(md5sums), mode: 0o644, modTime: now},
	)
}

func makeTarGzip(entries []tarEntry) ([]byte, error) {
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Size:     int64(len(entry.body)),
			ModTime:  entry.modTime,
			Typeflag: entry.typeFlag,
		}
		if err := writeTarEntry(tarWriter, header, entry.body); err != nil {
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	if err := gzipWriter.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func newArMember(name string, body []byte, now time.Time) (arMember, error) {
	if len(name) > 16 {
		return arMember{}, fmt.Errorf("ar member name is too long: %q", name)
	}
	header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, now.Unix(), 0, 0, 0o644, len(body))
	if len(header) != arHeaderSize {
		return arMember{}, fmt.Errorf("invalid ar header size for %q", name)
	}
	var member arMember
	copy(member.header[:], header)
	member.data = body
	return member, nil
}

func writePackageFile(path string, body []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".mkdeb-*")
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set output permissions: %w", err)
	}
	if _, err := temp.Write(body); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write output: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}
	return nil
}
