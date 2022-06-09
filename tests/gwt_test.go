package tests

import (
	"bytes"
	"fmt"
	"github.com/google/uuid"
	"github.com/vaiktorg/gwt"
	"testing"
	"time"
)

var (
	Value = gwt.Value{
		Issuer:    GlobalIssuer,
		Username:  "Va!kt0rg123",
		Timestamp: time.Now().Add(time.Second),
	}
	GlobalIssuer = "CompanyIssuerName"
	GlobalToken  gwt.Token
)

//Spice
var (
	Salt   = []byte(uuid.New().String())
	Pepper = []byte(uuid.New().String())
)

var Encoder = gwt.NewEncoder()
var SpicedEncoder = gwt.NewSpicedEncoder(gwt.Spice{
	Salt:   Salt,
	Pepper: Pepper,
})

var Decoder = gwt.NewDecoder()
var SpicedDecoder = gwt.NewSpicedDecoder(gwt.Spice{
	Salt:   Salt,
	Pepper: Pepper,
})

func TestGWT(t *testing.T) {
	t.Run("Encode", func(t *testing.T) {
		Encoder.Encode(Value, func(token gwt.Token, err error) {
			if err != nil || token.Token == "" {
				t.Error(err)
				t.Failed()
			}

			GlobalToken = token
			Value.Signature = token.Signature
		})

		fmt.Println(GlobalToken)
		fmt.Println(Value)

	})
	t.Run("Decode", func(t *testing.T) {
		Decoder.Decode(GlobalToken,
			func(value gwt.Value, err error) {
				if err != nil {
					t.Error(err)
					t.Failed()
				}
				if value.Issuer == "" {
					t.Error("issuer is empty")
					t.Failed()
				}

				if value.Username == "" {
					t.Error("username is empty")
					t.Failed()
				}

				if !value.Timestamp.After(time.Now()) {
					t.Error("timestamp should of not expired")
					t.Failed()
				}

				if bytes.Compare(value.Signature, Value.Signature) != 0 {
					t.Error("signature mismatch")
					t.Failed()
				}

				fmt.Println(value)
				fmt.Println(Value)
			})
	})
	t.Run("EncodeSpiced", func(t *testing.T) {
		SpicedEncoder.Encode(gwt.Value{
			Issuer:    GlobalIssuer,
			Username:  "Va!kt0rg123",
			Timestamp: time.Now().Add(time.Second),
		}, func(token gwt.Token, err error) {
			if err != nil || token.Token == "" {
				t.Error(err)
				t.Failed()
			}

			GlobalToken = token
			Value.Signature = token.Signature
		})

		fmt.Println(GlobalToken)

	})
	t.Run("DecodeSpiced", func(t *testing.T) {
		SpicedDecoder.Decode(GlobalToken,
			func(value gwt.Value, err error) {
				if err != nil {
					t.Error(err)
					t.Failed()
				}
				if value.Issuer == "" {
					t.Error("issuer is empty")
					t.Failed()
				}

				if value.Username == "" {
					t.Error("username is empty")
					t.Failed()
				}

				if !value.Timestamp.After(time.Now()) {
					t.Error("timestamp should of not expired")
					t.Failed()
				}

				if bytes.Compare(value.Signature, Value.Signature) != 0 {
					t.Error("signature mismatch")
					t.Failed()
				}

				fmt.Println(value)
			})
	})
}
