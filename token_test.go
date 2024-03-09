package gojwe_test

import (
	"fmt"
	"github.com/prongbang/gojwe"
	"testing"
)

func TestGenerate(t *testing.T) {
	type args struct {
		payload map[string]any
		key     string
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
				key: "bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1",
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New()
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

func TestVerify(t *testing.T) {
	type args struct {
		token string
		key   string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Should return true when verify success",
			args: args{
				key:   "bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1",
				token: "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJNR0tJZEpKdVlUdWprOFVMIiwidGFnIjoiNFc4SEMtX0JodHl0bUc0RnRqSGtmZyJ9.0K_MuyluKYA0zgsbWvpXI4_gvZkqQ-OaPvq_N6474K4.HYvnrRs9TI21bclM.2KFpmG-Ov6VS_C41Xg5ADRrfiQ.J1ZvGZkT0zWd80vBEMUK5g",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New()
			if got := j.Verify(tt.args.token, tt.args.key); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	type args struct {
		token string
		key   string
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
				key:   "bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1",
				token: "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJNR0tJZEpKdVlUdWprOFVMIiwidGFnIjoiNFc4SEMtX0JodHl0bUc0RnRqSGtmZyJ9.0K_MuyluKYA0zgsbWvpXI4_gvZkqQ-OaPvq_N6474K4.HYvnrRs9TI21bclM.2KFpmG-Ov6VS_C41Xg5ADRrfiQ.J1ZvGZkT0zWd80vBEMUK5g",
			},
			want:    "99999999999",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := gojwe.New()
			if got, err := j.Parse(tt.args.token, tt.args.key); fmt.Sprint(got["exp"]) != tt.want && err != nil != tt.wantErr {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkGenerate(b *testing.B) {
	j := gojwe.New()
	key := "bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1"
	payload := map[string]any{
		"exp": 999999999,
	}
	for i := 0; i < b.N; i++ {
		_, _ = j.Generate(payload, key)
	}
}

func BenchmarkParse(b *testing.B) {
	j := gojwe.New()
	key := "bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1"
	jwe := "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJNR0tJZEpKdVlUdWprOFVMIiwidGFnIjoiNFc4SEMtX0JodHl0bUc0RnRqSGtmZyJ9.0K_MuyluKYA0zgsbWvpXI4_gvZkqQ-OaPvq_N6474K4.HYvnrRs9TI21bclM.2KFpmG-Ov6VS_C41Xg5ADRrfiQ.J1ZvGZkT0zWd80vBEMUK5g"
	for i := 0; i < b.N; i++ {
		_, _ = j.Parse(jwe, key)
	}
}

func BenchmarkVerify(b *testing.B) {
	j := gojwe.New()
	key := "bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1"
	jwe := "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJNR0tJZEpKdVlUdWprOFVMIiwidGFnIjoiNFc4SEMtX0JodHl0bUc0RnRqSGtmZyJ9.0K_MuyluKYA0zgsbWvpXI4_gvZkqQ-OaPvq_N6474K4.HYvnrRs9TI21bclM.2KFpmG-Ov6VS_C41Xg5ADRrfiQ.J1ZvGZkT0zWd80vBEMUK5g"
	for i := 0; i < b.N; i++ {
		_ = j.Verify(jwe, key)
	}
}
