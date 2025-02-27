package utils

import (
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestEncrypted(field interface{}) bool {
	binaryField, ok := field.(bson.Binary)
	if !ok || (ok && binaryField.Subtype != 6) {
		return false
	}
	return true
}

func GetField(data bson.M, field string) interface{} {
	keys := strings.Split(field, ".")
	var current interface{} = data

	for _, key := range keys {
		if m, ok := current.(bson.M); ok {
			current = m[key]
		} else {
			return nil
		}
	}
	return current
}

// SetField sets a nested field in a bson.M object.
func SetField(data bson.M, field string, value interface{}) {
	keys := strings.Split(field, ".")
	var current interface{} = data

	for i, key := range keys {
		if i == len(keys)-1 {
			if m, ok := current.(bson.M); ok {
				m[key] = value
			}
			return
		}

		if m, ok := current.(bson.M); ok {
			if _, exists := m[key]; !exists {
				m[key] = bson.M{}
			}
			current = m[key]
		} else {
			return
		}
	}
}

// DeleteField removes a nested field from a bson.M object.
func DeleteField(data bson.M, field string) {
	keys := strings.Split(field, ".")
	var current interface{} = data

	for i, key := range keys {
		if m, ok := current.(bson.M); ok {
			if i == len(keys)-1 {
				delete(m, key)
			} else {
				current = m[key]
			}
		} else {
			return
		}
	}
}
