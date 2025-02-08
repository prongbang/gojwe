package gojwe_test

import (
	"encoding/hex"
	"fmt"
	"github.com/prongbang/gojwe"
	"testing"
)

var aesGcmKey, _ = hex.DecodeString("bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1")

func TestAesGcm256Generate(t *testing.T) {
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
				key: aesGcmKey,
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New(gojwe.AESGCM256)
			got, err := j.Generate(tt.args.payload, tt.args.key)

			fmt.Println(got)
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

func TestAesGcm256Verify(t *testing.T) {
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
				key:   aesGcmKey,
				token: "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJNR0tJZEpKdVlUdWprOFVMIiwidGFnIjoiNFc4SEMtX0JodHl0bUc0RnRqSGtmZyJ9.0K_MuyluKYA0zgsbWvpXI4_gvZkqQ-OaPvq_N6474K4.HYvnrRs9TI21bclM.2KFpmG-Ov6VS_C41Xg5ADRrfiQ.J1ZvGZkT0zWd80vBEMUK5g",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New(gojwe.AESGCM256)
			if got := j.Verify(tt.args.token, tt.args.key); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAesGcm256Parse(t *testing.T) {
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
				key:   aesGcmKey,
				token: "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJNR0tJZEpKdVlUdWprOFVMIiwidGFnIjoiNFc4SEMtX0JodHl0bUc0RnRqSGtmZyJ9.0K_MuyluKYA0zgsbWvpXI4_gvZkqQ-OaPvq_N6474K4.HYvnrRs9TI21bclM.2KFpmG-Ov6VS_C41Xg5ADRrfiQ.J1ZvGZkT0zWd80vBEMUK5g",
			},
			want:    "99999999999",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New(gojwe.AESGCM256)
			if got, err := j.Parse(tt.args.token, tt.args.key); fmt.Sprint(got["exp"]) != tt.want && err != nil != tt.wantErr {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkAesGcm256Generate(b *testing.B) {
	j := gojwe.New(gojwe.AESGCM256)
	payload := map[string]any{
		"exp": 999999999,
	}
	for i := 0; i < b.N; i++ {
		_, _ = j.Generate(payload, aesGcmKey)
	}
}

func BenchmarkAesGcm256Parse(b *testing.B) {
	j := gojwe.New(gojwe.AESGCM256)
	jwe := "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJNR0tJZEpKdVlUdWprOFVMIiwidGFnIjoiNFc4SEMtX0JodHl0bUc0RnRqSGtmZyJ9.0K_MuyluKYA0zgsbWvpXI4_gvZkqQ-OaPvq_N6474K4.HYvnrRs9TI21bclM.2KFpmG-Ov6VS_C41Xg5ADRrfiQ.J1ZvGZkT0zWd80vBEMUK5g"
	for i := 0; i < b.N; i++ {
		_, _ = j.Parse(jwe, aesGcmKey)
	}
}

func BenchmarkAesGcm256Verify(b *testing.B) {
	j := gojwe.New(gojwe.AESGCM256)
	jwe := "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJNR0tJZEpKdVlUdWprOFVMIiwidGFnIjoiNFc4SEMtX0JodHl0bUc0RnRqSGtmZyJ9.0K_MuyluKYA0zgsbWvpXI4_gvZkqQ-OaPvq_N6474K4.HYvnrRs9TI21bclM.2KFpmG-Ov6VS_C41Xg5ADRrfiQ.J1ZvGZkT0zWd80vBEMUK5g"
	for i := 0; i < b.N; i++ {
		_ = j.Verify(jwe, aesGcmKey)
	}
}
