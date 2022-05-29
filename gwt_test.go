package gwt

import (
	"fmt"
	"github.com/google/uuid"
	"testing"
)

var (
	GlobalIssuer    = "CompanyIssuerName"
	GlobalToken     = ""
	GlobalSignature = ""
)

var Gwt = NewDefaultGWT(GlobalIssuer)
var GwtWith = NewGWTWithSpice(GlobalIssuer, Spice{
	Salt:   []byte(uuid.New().String()),
	Pepper: []byte(uuid.New().String()),
})

func TestGWT(t *testing.T) {
	t.Run("Encode", func(t *testing.T) {
		token, err := Gwt.Encode("this is a string payload")
		if err != nil {
			t.Error(err)
			t.Failed()
		}

		GlobalToken = token.Token
		GlobalSignature = token.Sig

		fmt.Printf("%#+v\n", Gwt)
		fmt.Printf("%#+v\n", GlobalToken)
		fmt.Printf("%#+v\n", GlobalSignature)

	})

	t.Run("Decode", func(t *testing.T) {
		err := Gwt.Decode(GlobalToken)
		if err != nil {
			t.Error(err)
			t.Failed()
		}

		fmt.Printf("%#+v\n", Gwt)

	})

	t.Run("EncodeWith", func(t *testing.T) {
		token, err := GwtWith.Encode("this is a string payload")
		if err != nil {
			t.Error(err)
			t.Failed()
		}

		GlobalToken = token.Token
		GlobalSignature = token.Sig

		fmt.Printf("%#+v\n", Gwt)
		fmt.Printf("%#+v\n", GlobalToken)
		fmt.Printf("%#+v\n", GlobalSignature)

	})

	t.Run("DecodeWith", func(t *testing.T) {
		err := GwtWith.Decode(GlobalToken)
		if err != nil {
			t.Error(err)
			t.Failed()
		}

		fmt.Printf("%#+v\n", Gwt)

	})
}
