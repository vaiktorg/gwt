package gwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Spice struct {
	Salt   []byte
	Pepper []byte
}

type (
	Encoder struct {
		encode  chan Value
		resChan chan Token
		spice   Spice
		err     chan error
	}

	// Decoder ...
	Decoder struct {
		decode  chan Token
		resChan chan Value
		spc     Spice
		err     chan error
	}

	// Value generates the user's Token
	Value struct {
		Issuer    string    // where the token originated
		Username  string    // who the token belongs to
		Timestamp time.Time // timeout is enforced
		Signature []byte    // ___.___.OOO  Last section of Token
	}

	// Token gets delivered to the user.
	Token struct {
		Token     string // "1a2.b3c.4d5" [data -> byte -> b64]
		Signature []byte // ___.___.OOO  Last section of Token
	}
)

const (
	TokenName = "gwt"
)

const (
	ErrorTokenParts        = "there are more or less parts of the token"
	ErrorNoTokProvided     = "no token provided"
	ErrorFailedToDecode    = "failed to decode token signature"
	ErrorFailedToEncodeSig = "failed to encode token signature"
	ErrorFailedToEncodePL  = "failed to encode token payload"
	ErrorSignatureNotMatch = "signatures do not match"
)

func NewEncoder() *Encoder {
	return &Encoder{
		encode:  make(chan Value),
		resChan: make(chan Token),
		err:     make(chan error),
	}
}

func NewSpicedEncoder(spice Spice) *Encoder {
	return &Encoder{
		spice:   spice,
		encode:  make(chan Value),
		resChan: make(chan Token),
		err:     make(chan error),
	}
}

func NewDecoder() *Decoder {
	return &Decoder{
		decode:  make(chan Token),
		resChan: make(chan Value),
		err:     make(chan error),
	}
}

func NewSpicedDecoder(spice Spice) *Decoder {
	return &Decoder{
		spc:     spice,
		decode:  make(chan Token),
		resChan: make(chan Value),
		err:     make(chan error),
	}
}

func (e *Encoder) Encode(values Value, res func(token Token, err error)) {
	go e.encodeValue()

	e.encode <- values

	select {
	case _ = <-e.err:
		res(Token{}, errors.New(ErrorFailedToDecode))
	case val := <-e.resChan:
		res(val, nil)
	}
}
func (e *Encoder) encodeValue() {
	value := <-e.encode

	// Value JSON string
	valueBuffer := new(bytes.Buffer)
	err := json.NewEncoder(valueBuffer).Encode(value)
	if err != nil {
		e.err <- errors.New(ErrorFailedToEncodePL)
		return
	}

	// ------------------------------------------------------------------------------------------------
	// Gen Signature
	hashSignature, err := genSignature(valueBuffer.Bytes(), &e.spice)
	if err != nil {
		e.err <- err
		return
	}

	// ------------------------------------------------------------------------------------------------
	// Encode to B64
	b64value, b64signature := encodeB64(valueBuffer.Bytes(), hashSignature)

	// ------------------------------------------------------------------------------------------------
	// Results in token "b64Header.b64Payload.b64Signature"
	e.resChan <- Token{
		Token: strings.Join([]string{
			string(b64value),
			string(b64signature),
		}, "."),
		Signature: hashSignature}
}

func encodeB64(valueBuffer, hashSignature []byte) (b64value, b64signature []byte) {
	// ----------------------------------------------------------------------------------------------
	// Signature Encoding
	b64signature = make([]byte, base64.URLEncoding.EncodedLen(len(hashSignature)))
	base64.URLEncoding.Encode(b64signature, hashSignature)

	//----------------------------------------------------------------------------------------------
	// Header Encoding
	b64value = make([]byte, base64.URLEncoding.EncodedLen(len(valueBuffer)))
	base64.URLEncoding.Encode(b64value, valueBuffer)

	return b64value, b64signature
}

func (d *Decoder) Decode(token Token, res func(value Value, err error)) {
	go d.decodeToken()

	d.decode <- token

	select {
	case err := <-d.err:
		res(Value{}, err)
	case val := <-d.resChan:
		res(val, nil)
	}
}
func (d *Decoder) decodeToken() {
	tkn := <-d.decode
	if tkn.Token == "" {
		d.err <- errors.New(ErrorNoTokProvided)
		return
	}

	// tkn := tknB64[0]
	// sig := tknB64[1]
	tknB64 := strings.Split(tkn.Token, ".")
	if len(tknB64) < 2 || len(tknB64) > 2 {
		d.err <- errors.New(ErrorTokenParts)
	}

	tknBuff, err := decodeB64(tknB64[0])
	if err != nil {
		d.err <- err
		return
	}

	sigBuff, err := decodeB64(tknB64[1])
	if err != nil {
		d.err <- err
		return
	}

	// ------------------------------------------------------------------------------------------------
	// Signature
	hashSignature, err := genSignature(tknBuff, &d.spc)
	if err != nil {
		d.err <- err
		return
	}

	// ------------------------------------------------------------------------------------------------
	// Validate
	if !bytes.Equal(hashSignature, sigBuff) {
		d.err <- errors.New(ErrorSignatureNotMatch)
		return
	}

	// If signatures match, keep going with decoding information.
	// ------------------------------------------------------------------------------------------------
	// Decode data
	val := Value{}
	err = json.NewDecoder(bytes.NewReader(tknBuff)).Decode(&val)
	if err != nil {
		d.err <- err
		return
	}

	val.Signature = hashSignature
	d.resChan <- val
}

func decodeB64(gwt string) ([]byte, error) {
	// ------------------------------------------------------------------------------------------------
	// B64 Decoding
	// Signature
	tokenBuff, err := base64.URLEncoding.DecodeString(gwt)
	if err != nil {
		return nil, err
	}

	return tokenBuff, nil
}
func genSignature(tokenBuff []byte, spice *Spice) ([]byte, error) {
	//Generate gwt Signature from decoded payload
	hash := hmac.New(sha256.New, spice.Salt)
	_, err := hash.Write(tokenBuff)
	if err != nil {
		return nil, errors.New(ErrorFailedToEncodeSig)
	}

	return hash.Sum(spice.Pepper), nil
}
