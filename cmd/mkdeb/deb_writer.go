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
	"path/filepath"
	"strings"
	"time"
)

type debFile struct {
	source      string
	destination string
}

type tarEntry struct {
	name    string
	body    []byte
	mode    int64
	modTime time.Time
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

func packageFiles(o options) ([]debFile, error) {
	files := []debFile{
		{o.binarySrc, o.binaryDest},
		{o.unitSrc, unitDestination},
		{o.confSrc, confDestination},
	}
	if _, err := os.Stat(o.licenseSrc); err == nil {
		files = append(files, debFile{o.licenseSrc, licenseDest})
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
		mode:    int64(info.Mode().Perm()),
		modTime: info.ModTime(),
	}, nil
}

func controlEntries(o options, md5sums string, installedBytes int64, now time.Time) []tarEntry {
	installedSize := (installedBytes + 1023) / 1024
	control := fmt.Sprintf(
		"Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: %s <>\n"+
			"Installed-Size: %d\nSection: %s\nHomepage: %s\nDepends: %s\n"+
			"Description: %s\n %s\n",
		packageName, o.version, o.arch, maintainer, installedSize, section, url,
		packageRelations(), summary, strings.ReplaceAll(description, "\n", "\n "),
	)
	return []tarEntry{
		{"postinst", []byte(postinstScript), 0o755, now},
		{"prerm", []byte(prermScript), 0o755, now},
		{"postrm", []byte(postrmScript), 0o755, now},
		{"conffiles", []byte(confDestination + "\n"), 0o644, now},
		{"control", []byte(control), 0o644, now},
		{"md5sums", []byte(md5sums), 0o644, now},
	}
}

func makeTarGzip(entries []tarEntry) ([]byte, error) {
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name:    entry.name,
			Mode:    entry.mode,
			Size:    int64(len(entry.body)),
			ModTime: entry.modTime,
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
