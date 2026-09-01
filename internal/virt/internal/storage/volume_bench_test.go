package storage

import "testing"

const benchmarkVolumeChunkSize = 64 * 1024

type benchmarkVolumeReader struct{}

func (benchmarkVolumeReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}

//nolint:gocognit // The size matrix and per-chunk validation intentionally remain in one benchmark.
func BenchmarkStreamReaderChunksWithProgress(b *testing.B) {
	for _, tc := range []struct {
		name       string
		chunkCount int
	}{
		{name: "chunks=10", chunkCount: 10},
		{name: "chunks=100", chunkCount: 100},
		{name: "chunks=1000", chunkCount: 1000},
	} {
		b.Run(tc.name, func(b *testing.B) {
			chunks := StreamReaderChunksWithProgress(benchmarkVolumeReader{}, func(int) {})
			b.SetBytes(int64(tc.chunkCount) * benchmarkVolumeChunkSize)
			b.ReportAllocs()

			for b.Loop() {
				for range tc.chunkCount {
					chunk, err := chunks(nil, benchmarkVolumeChunkSize)
					if err != nil {
						b.Fatal(err)
					}
					if len(chunk) != benchmarkVolumeChunkSize {
						b.Fatalf("chunk length = %d, want %d", len(chunk), benchmarkVolumeChunkSize)
					}
				}
			}
		})
	}
}
