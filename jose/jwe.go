/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/yangalan0903/sepp/jose/json"
)

// rawJSONWebEncryption represents a raw JWE JSON object. Used for parsing/serializing.
type RawJSONWebEncryption struct {
	Protected    *ByteBuffer        `json:"protected,omitempty"`
	Unprotected  *RawHeader         `json:"unprotected,omitempty"`
	Header       *RawHeader         `json:"header,omitempty"`
	Recipients   []rawRecipientInfo `json:"recipients,omitempty"`
	Aad          *ByteBuffer        `json:"aad,omitempty"`
	EncryptedKey *ByteBuffer        `json:"encrypted_key,omitempty"`
	Iv           *ByteBuffer        `json:"iv,omitempty"`
	Ciphertext   *ByteBuffer        `json:"ciphertext,omitempty"`
	Tag          *ByteBuffer        `json:"tag,omitempty"`
}

// rawRecipientInfo represents a raw JWE Per-Recipient header JSON object. Used for parsing/serializing.
type rawRecipientInfo struct {
	Header       *RawHeader `json:"header,omitempty"`
	EncryptedKey string     `json:"encrypted_key,omitempty"`
}

// JSONWebEncryption represents an encrypted JWE object after parsing.
type JSONWebEncryption struct {
	Header                   Header
	protected, unprotected   *RawHeader
	recipients               []recipientInfo
	aad, iv, ciphertext, tag []byte
	Original                 *RawJSONWebEncryption
}

// recipientInfo represents a raw JWE Per-Recipient header JSON object after parsing.
type recipientInfo struct {
	header       *RawHeader
	encryptedKey []byte
}

// GetAuthData retrieves the (optional) authenticated data attached to the object.
func (obj JSONWebEncryption) GetAuthData() []byte {
	if obj.aad != nil {
		out := make([]byte, len(obj.aad))
		copy(out, obj.aad)
		return out
	}

	return nil
}

// Get the merged header values
func (obj JSONWebEncryption) mergedHeaders(recipient *recipientInfo) RawHeader {
	out := RawHeader{}
	out.merge(obj.protected)
	out.merge(obj.unprotected)

	if recipient != nil {
		out.merge(recipient.header)
	}

	return out
}

// Get the additional authenticated data from a JWE object.
func (obj JSONWebEncryption) computeAuthData() []byte {
	var protected string

	if obj.Original != nil && obj.Original.Protected != nil {
		protected = obj.Original.Protected.base64()
	} else if obj.protected != nil {
		protected = base64.RawURLEncoding.EncodeToString(mustSerializeJSON((obj.protected)))
	} else {
		protected = ""
	}

	output := []byte(protected)
	if obj.aad != nil {
		output = append(output, '.')
		output = append(output, []byte(base64.RawURLEncoding.EncodeToString(obj.aad))...)
	}

	return output
}

// ParseEncrypted parses an encrypted message in compact or full serialization format.
func ParseEncrypted(input string) (*JSONWebEncryption, error) {
	input = stripWhitespace(input)
	if strings.HasPrefix(input, "{") {
		return parseEncryptedFull(input)
	}

	return parseEncryptedCompact(input)
}

// parseEncryptedFull parses a message in compact format.
func parseEncryptedFull(input string) (*JSONWebEncryption, error) {
	var parsed RawJSONWebEncryption
	err := json.Unmarshal([]byte(input), &parsed)
	if err != nil {
		return nil, err
	}

	return parsed.Sanitized()
}

// sanitized produces a cleaned-up JWE object from the raw JSON.
func (parsed *RawJSONWebEncryption) Sanitized() (*JSONWebEncryption, error) {
	obj := &JSONWebEncryption{
		Original:    parsed,
		unprotected: parsed.Unprotected,
	}

	// Check that there is not a nonce in the unprotected headers
	if parsed.Unprotected != nil {
		if nonce := parsed.Unprotected.getNonce(); nonce != "" {
			return nil, ErrUnprotectedNonce
		}
	}
	if parsed.Header != nil {
		if nonce := parsed.Header.getNonce(); nonce != "" {
			return nil, ErrUnprotectedNonce
		}
	}

	if parsed.Protected != nil && len(parsed.Protected.bytes()) > 0 {
		err := json.Unmarshal(parsed.Protected.bytes(), &obj.protected)
		if err != nil {
			return nil, fmt.Errorf("square/go-jose: invalid protected header: %s, %s", err, parsed.Protected.base64())
		}
	}

	// Note: this must be called _after_ we parse the protected header,
	// otherwise fields from the protected header will not get picked up.
	var err error
	mergedHeaders := obj.mergedHeaders(nil)
	obj.Header, err = mergedHeaders.sanitized()
	if err != nil {
		return nil, fmt.Errorf("square/go-jose: cannot sanitize merged headers: %v (%v)", err, mergedHeaders)
	}

	if len(parsed.Recipients) == 0 {
		obj.recipients = []recipientInfo{
			{
				header:       parsed.Header,
				encryptedKey: parsed.EncryptedKey.bytes(),
			},
		}
	} else {
		obj.recipients = make([]recipientInfo, len(parsed.Recipients))
		for r := range parsed.Recipients {
			encryptedKey, err := base64.RawURLEncoding.DecodeString(parsed.Recipients[r].EncryptedKey)
			if err != nil {
				return nil, err
			}

			// Check that there is not a nonce in the unprotected header
			if parsed.Recipients[r].Header != nil && parsed.Recipients[r].Header.getNonce() != "" {
				return nil, ErrUnprotectedNonce
			}

			obj.recipients[r].header = parsed.Recipients[r].Header
			obj.recipients[r].encryptedKey = encryptedKey
		}
	}

	for _, recipient := range obj.recipients {
		headers := obj.mergedHeaders(&recipient)
		if headers.getAlgorithm() == "" || headers.getEncryption() == "" {
			return nil, fmt.Errorf("square/go-jose: message is missing alg/enc headers")
		}
	}

	obj.iv = parsed.Iv.bytes()
	obj.ciphertext = parsed.Ciphertext.bytes()
	obj.tag = parsed.Tag.bytes()
	obj.aad = parsed.Aad.bytes()

	return obj, nil
}

// parseEncryptedCompact parses a message in compact format.
func parseEncryptedCompact(input string) (*JSONWebEncryption, error) {
	parts := strings.Split(input, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("square/go-jose: compact JWE format must have five parts")
	}

	rawProtected, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}

	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}

	raw := &RawJSONWebEncryption{
		Protected:    newBuffer(rawProtected),
		EncryptedKey: newBuffer(encryptedKey),
		Iv:           newBuffer(iv),
		Ciphertext:   newBuffer(ciphertext),
		Tag:          newBuffer(tag),
	}

	return raw.Sanitized()
}

// CompactSerialize serializes an object using the compact serialization format.
func (obj JSONWebEncryption) CompactSerialize() (string, error) {
	if len(obj.recipients) != 1 || obj.unprotected != nil ||
		obj.protected == nil || obj.recipients[0].header != nil {
		return "", ErrNotSupported
	}

	serializedProtected := mustSerializeJSON(obj.protected)

	return fmt.Sprintf(
		"%s.%s.%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(serializedProtected),
		base64.RawURLEncoding.EncodeToString(obj.recipients[0].encryptedKey),
		base64.RawURLEncoding.EncodeToString(obj.iv),
		base64.RawURLEncoding.EncodeToString(obj.ciphertext),
		base64.RawURLEncoding.EncodeToString(obj.tag)), nil
}

// FullSerialize serializes an object using the full JSON serialization format.
func (obj JSONWebEncryption) FullSerialize() string {
	raw := RawJSONWebEncryption{
		Unprotected:  obj.unprotected,
		Iv:           newBuffer(obj.iv),
		Ciphertext:   newBuffer(obj.ciphertext),
		EncryptedKey: newBuffer(obj.recipients[0].encryptedKey),
		Tag:          newBuffer(obj.tag),
		Aad:          newBuffer(obj.aad),
		Recipients:   []rawRecipientInfo{},
	}

	if len(obj.recipients) > 1 {
		for _, recipient := range obj.recipients {
			info := rawRecipientInfo{
				Header:       recipient.header,
				EncryptedKey: base64.RawURLEncoding.EncodeToString(recipient.encryptedKey),
			}
			raw.Recipients = append(raw.Recipients, info)
		}
	} else {
		// Use flattened serialization
		raw.Header = obj.recipients[0].header
		raw.EncryptedKey = newBuffer(obj.recipients[0].encryptedKey)
	}

	if obj.protected != nil {
		raw.Protected = newBuffer(mustSerializeJSON(obj.protected))
	}

	return string(mustSerializeJSON(raw))
}
