package main

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

type debFile struct {
	source      string
	destination string
	mode        int64
}

type tarEntry struct {
	name     string
	body     []byte
	mode     int64
	modTime  time.Time
	typeFlag byte
}

func writeDebArchive(o options) error {
	files, err := packageFiles(o)
	if err != nil {
		return err
	}

	dataEntries := make([]tarEntry, 0, len(files))
	var md5sums strings.Builder
	var installedBytes int64
	for _, file := range files {
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
	controlArchive, err := makeTarGzip(controlEntries(o, md5sums.String(), installedBytes, now))
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
	return writePackageFile(o.out, writeAr(members))
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

// packageFiles returns the install manifest. Modes are fixed here rather than
// copied from the source files so the package is deterministic regardless of the
// build checkout's umask. The config file is installed 0640 (root read/write, no
// group or world read) because it can hold secrets: a LOCAL_USER_SHA256 list of
// password digests and the SSH tunnel key passphrase
// (SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE). The data archive owns every entry as
// root:root (uid/gid 0), so 0640 keeps the file readable only by root. The other
// files carry no secrets and use the conventional world-readable modes.
func packageFiles(o options) ([]debFile, error) {
	files := []debFile{
		{o.binarySrc, o.binaryDest, 0o755},
		{o.unitSrc, unitDestination, 0o644},
		{o.confSrc, confDestination, 0o640},
	}
	if _, err := os.Stat(o.licenseSrc); err == nil {
		files = append(files, debFile{o.licenseSrc, licenseDest, 0o644})
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat license: %w", err)
	}
	return files, nil
}

func readPackageFile(file debFile) (tarEntry, error) {
	cleanDestination := filepath.ToSlash(filepath.Clean(file.destination))
	if !strings.HasPrefix(cleanDestination, "/") || cleanDestination == "/" {
		return tarEntry{}, fmt.Errorf("package destination must be an absolute file path: %q", file.destination)
	}

	source, err := os.Open(file.source) //nolint:gosec // Sources are explicitly supplied packaging inputs.
	if err != nil {
		return tarEntry{}, fmt.Errorf("open %s: %w", file.source, err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return tarEntry{}, fmt.Errorf("stat %s: %w", file.source, err)
	}
	if !info.Mode().IsRegular() {
		return tarEntry{}, fmt.Errorf("package source is not a regular file: %s", file.source)
	}
	body, err := io.ReadAll(source)
	if err != nil {
		return tarEntry{}, fmt.Errorf("read %s: %w", file.source, err)
	}
	return tarEntry{
		name:    strings.TrimPrefix(cleanDestination, "/"),
		body:    body,
		mode:    file.mode,
		modTime: info.ModTime(),
	}, nil
}

func controlEntries(o options, md5sums string, installedBytes int64, now time.Time) []tarEntry {
	installedSize := (installedBytes + 1023) / 1024
	control := fmt.Sprintf(
		"Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: %s <%s>\n"+
			"Installed-Size: %d\nSection: %s\nHomepage: %s\nDepends: %s\n"+
			"Description: %s\n %s\n",
		packageName, o.version, o.arch, maintainer, maintainerEmail, installedSize, section, url,
		packageRelations(), summary, strings.ReplaceAll(description, "\n", "\n "),
	)
	return []tarEntry{
		{name: "postinst", body: []byte(postinstScript), mode: 0o755, modTime: now},
		{name: "prerm", body: []byte(prermScript), mode: 0o755, modTime: now},
		{name: "postrm", body: []byte(postrmScript), mode: 0o755, modTime: now},
		{name: "conffiles", body: []byte(confDestination + "\n"), mode: 0o644, modTime: now},
		{name: "control", body: []byte(control), mode: 0o644, modTime: now},
		{name: "md5sums", body: []byte(md5sums), mode: 0o644, modTime: now},
	}
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
