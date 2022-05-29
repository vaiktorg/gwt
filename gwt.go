package gwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"strings"
	"time"
)

type Spice struct {
	Salt   []byte
	Pepper []byte
}

type (
	Header struct {
		ID        string
		Issuer    string
		Timestamp time.Time
	}

	GWT struct {
		Header    Header
		Payload   interface{} // Use type assertion to get your expected payload package.
		Signature []byte      // Token Signature
		spice     Spice
	}
	Token struct {
		Token     string
		Signature string
	}
)

const (
	TokenName = "gwt"
)

const (
	ErrorMissingParts      = "parts of token are missing"
	ErrorNoTokProvided     = "no token provided"
	ErrorFailedToDecode    = "failed to decode token signature"
	ErrorFailedToEncodeSig = "failed to encode token signature"
	ErrorFailedToEncodePL  = "failed to encode token payload"
	ErrorFailedToEncodeHdr = "failed to encode token header"
	ErrorNilArgument       = "argument payload is nil"
	ErrorSignatureNotMatch = "signatures do not match"
)

func NewDefaultGWT(issuer string) *GWT {
	t := &GWT{
		Header: Header{
			ID:        uuid.NewString(),
			Issuer:    issuer,
			Timestamp: time.Now(),
		},
	}
	return t
}

func NewGWTWithSpice(issuer string, spice Spice) *GWT {
	t := &GWT{
		Header: Header{
			ID:        uuid.NewString(),
			Issuer:    issuer,
			Timestamp: time.Now(),
		},
		spice: spice,
	}
	return t
}

func (g *GWT) Encode(payload interface{}) (token *Token, err error) {
	if payload == nil {
		return nil, errors.New(ErrorNilArgument)
	}

	// Payload JSON string
	payloadBuffer := new(bytes.Buffer)
	err = json.NewEncoder(payloadBuffer).Encode(payload)
	if err != nil {
		return nil, errors.New(ErrorFailedToEncodePL)
	}

	// Header JSON string
	headerBuffer := new(bytes.Buffer)
	err = json.NewEncoder(headerBuffer).Encode(&Header{
		ID:        g.Header.ID,
		Issuer:    g.Header.Issuer,
		Timestamp: time.Now(),
	})

	if err != nil {
		return nil, errors.New(ErrorFailedToEncodeHdr)
	}

	// ----------------------------------------------------------------------------------------------
	// Signature Encoding
	hash := hmac.New(sha256.New, g.spice.Salt)
	_, err = hash.Write(append(headerBuffer.Bytes(), payloadBuffer.Bytes()...))
	if err != nil {
		return nil, errors.New(ErrorFailedToEncodeSig)
	}

	hashSignature := hash.Sum(g.spice.Pepper)

	b64signature := make([]byte, base64.URLEncoding.EncodedLen(len(hashSignature)))
	base64.URLEncoding.Encode(b64signature, hashSignature)

	// ----------------------------------------------------------------------------------------------
	// Payload Encoding
	b64payload := make([]byte, base64.URLEncoding.EncodedLen(payloadBuffer.Len()))
	base64.URLEncoding.Encode(b64payload, payloadBuffer.Bytes())

	//----------------------------------------------------------------------------------------------
	// Header Encoding
	b64header := make([]byte, base64.URLEncoding.EncodedLen(headerBuffer.Len()))
	base64.URLEncoding.Encode(b64header, headerBuffer.Bytes())
	//-----------

	// Results in token "b64Header.b64Payload.b64Signature"
	return &Token{
			Token: strings.Join([]string{
				string(b64header),
				string(b64payload),
				string(b64signature),
			}, "."),
			Signature: string(b64signature),
		},
		nil
}

func (g *GWT) Decode(tkn string) error {
	if tkn == "" {
		return errors.New(ErrorNoTokProvided)
	}

	// Split Message
	gwtParts := strings.Split(tkn, ".")
	if len(gwtParts) > 3 || len(gwtParts) < 3 {
		return errors.New(ErrorMissingParts)
	}

	// ------------------------------------------------------------------------------------------------
	// B64 Decoding
	// Signature
	signatureBuff, err := base64.URLEncoding.DecodeString(gwtParts[2])
	if err != nil {
		return err
	}

	// Payload
	payloadBuff, err := base64.URLEncoding.DecodeString(gwtParts[1])
	if err != nil {
		return err
	}

	// Header
	headerBuff, err := base64.URLEncoding.DecodeString(gwtParts[0])
	if err != nil {
		return err
	}

	// ------------------------------------------------------------------------------------------------
	// Decode data
	err = json.NewDecoder(bytes.NewReader(headerBuff)).Decode(&g.Header)
	if err != nil {
		return errors.New(ErrorFailedToDecode)
	}

	err = json.NewDecoder(bytes.NewReader(payloadBuff)).Decode(&g.Payload)
	if err != nil {
		return errors.New(ErrorFailedToDecode)
	}

	// ------------------------------------------------------------------------------------------------
	// Signature Validation

	//Generate gwt Signature from decoded payload
	hash := hmac.New(sha256.New, g.spice.Salt)
	_, err = hash.Write(append(headerBuff, payloadBuff...))
	if err != nil {
		return errors.New(ErrorFailedToEncodeSig)
	}

	hashSignature := hash.Sum(g.spice.Pepper)

	// Validate
	if !bytes.Equal(hashSignature, signatureBuff) {
		return errors.New(ErrorSignatureNotMatch)
	}

	g.Signature = hashSignature
	return nil
}
