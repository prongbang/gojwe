package gojwe_test

import (
	"encoding/hex"
	"fmt"
	"github.com/prongbang/gojwe"
	"testing"
)

var chaCha20Key, _ = hex.DecodeString("bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1")

func TestChaCha20Generate(t *testing.T) {
	type args struct {
		payload map[string]any
		key     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Should return jwe token when generate token success",
			args: args{
				payload: map[string]any{
					"exp": 99999999999,
				},
				key: chaCha20Key,
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New(gojwe.ChaCha20)
			got, err := j.Generate(tt.args.payload, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if valid := j.Verify(got, tt.args.key); valid != tt.want {
				t.Errorf("Generate() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChaCha20Verify(t *testing.T) {
	type args struct {
		token string
		key   []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Should return true when verify success",
			args: args{
				key:   chaCha20Key,
				token: "eyJhbGciOiJkaXIiLCJlbmMiOiJDMjBQIiwiaXYiOiI4anpnczN0WnczYmpnMkpKIiwidGFnIjoiN3l5UmJhSDRtMjlKVm9YY2E0bnR1ZyJ9.m-zFgnUbuss0Ju1YfE8R1naxCQ.Xkpx9QtDkRR4Tp5DH4pJ89i2Zy7KzrJ7uAt1Cyak2sA",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New(gojwe.ChaCha20)
			if got := j.Verify(tt.args.token, tt.args.key); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChaCha20Parse(t *testing.T) {
	type args struct {
		token string
		key   []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Should return exp payload when parse success",
			args: args{
				key:   chaCha20Key,
				token: "eyJhbGciOiJkaXIiLCJlbmMiOiJDMjBQIiwiaXYiOiI4anpnczN0WnczYmpnMkpKIiwidGFnIjoiN3l5UmJhSDRtMjlKVm9YY2E0bnR1ZyJ9.m-zFgnUbuss0Ju1YfE8R1naxCQ.Xkpx9QtDkRR4Tp5DH4pJ89i2Zy7KzrJ7uAt1Cyak2sA",
			},
			want:    "99999999999",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New(gojwe.ChaCha20)
			if got, err := j.Parse(tt.args.token, tt.args.key); fmt.Sprint(got["exp"]) != tt.want && err != nil != tt.wantErr {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkChaCha20Generate(b *testing.B) {
	j := gojwe.New(gojwe.ChaCha20)
	payload := map[string]any{
		"exp": 999999999,
	}
	for i := 0; i < b.N; i++ {
		_, err := j.Generate(payload, chaCha20Key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Parse(b *testing.B) {
	j := gojwe.New(gojwe.ChaCha20)
	jwe := "eyJhbGciOiJkaXIiLCJlbmMiOiJDMjBQIiwiaXYiOiI4anpnczN0WnczYmpnMkpKIiwidGFnIjoiN3l5UmJhSDRtMjlKVm9YY2E0bnR1ZyJ9.m-zFgnUbuss0Ju1YfE8R1naxCQ.Xkpx9QtDkRR4Tp5DH4pJ89i2Zy7KzrJ7uAt1Cyak2sA"
	for i := 0; i < b.N; i++ {
		_, _ = j.Parse(jwe, chaCha20Key)
	}
}

func BenchmarkChaCha20Verify(b *testing.B) {
	j := gojwe.New(gojwe.ChaCha20)
	jwe := "eyJhbGciOiJkaXIiLCJlbmMiOiJDMjBQIiwiaXYiOiI4anpnczN0WnczYmpnMkpKIiwidGFnIjoiN3l5UmJhSDRtMjlKVm9YY2E0bnR1ZyJ9.m-zFgnUbuss0Ju1YfE8R1naxCQ.Xkpx9QtDkRR4Tp5DH4pJ89i2Zy7KzrJ7uAt1Cyak2sA"
	for i := 0; i < b.N; i++ {
		_ = j.Verify(jwe, chaCha20Key)
	}
}
