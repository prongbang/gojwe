package gojwe_test

import (
	"encoding/hex"
	"fmt"
	"github.com/prongbang/gojwe"
	"testing"
)

var xChaCha20Key, _ = hex.DecodeString("bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1")

func TestXChaCha20Generate(t *testing.T) {
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
				key: xChaCha20Key,
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New(gojwe.XChaCha20)
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

func TestXChaCha20Verify(t *testing.T) {
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
				key:   xChaCha20Key,
				token: "eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCIsIml2IjoiNDIzMzQwdFJyMHRZT1lRR1M5OVYzb3hVbzZxbHQ0eGsiLCJ0YWciOiJTa1BZeS1TM243Y2RlSVQ1bGQ1UDl3In0.d6MSkUX8HlGOkonJr2IcutfPSg.F-LyJPPAPCzA8buyo6DDwVNYQc4QdMTMjk95zaoT7IQ",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New(gojwe.XChaCha20)
			if got := j.Verify(tt.args.token, tt.args.key); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXChaCha20Parse(t *testing.T) {
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
				key:   xChaCha20Key,
				token: "eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCIsIml2IjoiNDIzMzQwdFJyMHRZT1lRR1M5OVYzb3hVbzZxbHQ0eGsiLCJ0YWciOiJTa1BZeS1TM243Y2RlSVQ1bGQ1UDl3In0.d6MSkUX8HlGOkonJr2IcutfPSg.F-LyJPPAPCzA8buyo6DDwVNYQc4QdMTMjk95zaoT7IQ",
			},
			want:    "99999999999",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New(gojwe.XChaCha20)
			if got, err := j.Parse(tt.args.token, tt.args.key); fmt.Sprint(got["exp"]) != tt.want && err != nil != tt.wantErr {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkXChaCha20Generate(b *testing.B) {
	j := gojwe.New(gojwe.XChaCha20)
	payload := map[string]any{
		"exp": 999999999,
	}
	for i := 0; i < b.N; i++ {
		_, _ = j.Generate(payload, aesGcmKey)
	}
}

func BenchmarkXChaCha20Parse(b *testing.B) {
	j := gojwe.New(gojwe.XChaCha20)
	jwe := "eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCIsIml2IjoiNDIzMzQwdFJyMHRZT1lRR1M5OVYzb3hVbzZxbHQ0eGsiLCJ0YWciOiJTa1BZeS1TM243Y2RlSVQ1bGQ1UDl3In0.d6MSkUX8HlGOkonJr2IcutfPSg.F-LyJPPAPCzA8buyo6DDwVNYQc4QdMTMjk95zaoT7IQ"
	for i := 0; i < b.N; i++ {
		_, _ = j.Parse(jwe, aesGcmKey)
	}
}

func BenchmarkXChaCha20Verify(b *testing.B) {
	j := gojwe.New(gojwe.XChaCha20)
	jwe := "eyJhbGciOiJkaXIiLCJlbmMiOiJYQzIwUCIsIml2IjoiNDIzMzQwdFJyMHRZT1lRR1M5OVYzb3hVbzZxbHQ0eGsiLCJ0YWciOiJTa1BZeS1TM243Y2RlSVQ1bGQ1UDl3In0.d6MSkUX8HlGOkonJr2IcutfPSg.F-LyJPPAPCzA8buyo6DDwVNYQc4QdMTMjk95zaoT7IQ"
	for i := 0; i < b.N; i++ {
		_ = j.Verify(jwe, aesGcmKey)
	}
}
