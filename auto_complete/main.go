package main

import (
	"C"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	mdb "sde/csfle/mongodb"
	utils "sde/csfle/utils"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func main() {
	var (
		keyVaultDB       = "__encryption"
		keyVaultColl     = "__keyVault"
		keySpace         = keyVaultDB + "." + keyVaultColl
		caFile           = "/data/pki/ca.pem"
		keyCertFile      = "/data/pki/client-0.pem"
		kmipEndpoint     = "kmip-0:5696"
		cryptSharedPath  = "/data/lib/mongo_crypt_v1.so"
		username         = "app_user"
		password         = "SuperP@ssword123!"
		connectionString = "mongodb://mongodb-0:27017/?replicaSet=rs0&tls=true"
		exitCode         = 0
		kmipTLSConfig    *tls.Config
		result           *mongo.InsertOneResult
		findResult       bson.M
		dek              bson.Binary
		err              error
		encryptedDB      = "companyData"
		encryptedColl    = "employee"
	)

	defer func() {
		os.Exit(exitCode)
	}()

	provider := "kmip"
	kmsProvider := map[string]map[string]interface{}{
		provider: {
			"endpoint": kmipEndpoint,
		},
	}

	// Set the KMIP TLS options
	kmsTLSOptions := make(map[string]*tls.Config)
	tlsOptions := map[string]interface{}{
		"tlsCAFile":             caFile,
		"tlsCertificateKeyFile": keyCertFile,
	}
	kmipTLSConfig, err = options.BuildTLSConfig(tlsOptions)
	if err != nil {
		fmt.Printf("Cannot create KMS TLS Config: %s\n", err)
		exitCode = 1
		return
	}
	kmsTLSOptions["kmip"] = kmipTLSConfig

	mdb, err := mdb.NewMDB(connectionString, username, password, caFile, kmsProvider, keySpace, kmsTLSOptions, cryptSharedPath)
	if err != nil {
		fmt.Printf("MDB client error: %s\n", err)
		exitCode = 1
		return
	}

	err = mdb.CreateManualEncryptionClient()
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	firstname, lastname := utils.NameGenerator()
	payload := bson.M{
		"name": bson.M{
			"firstName":  firstname,
			"lastName":   lastname,
			"otherNames": nil,
		},
		"address": bson.M{
			"streetAddress": "29 Bson Street",
			"suburbCounty":  "Mongoville",
			"stateProvince": "Victoria",
			"zipPostcode":   "3999",
			"country":       "Oz",
		},
		"dob":           time.Date(1999, 1, 12, 0, 0, 0, 0, time.Local),
		"phoneNumber":   "1800MONGO",
		"salary":        999999.99,
		"taxIdentifier": "78SDSSWN001",
		"role":          []string{"Student"},
	}

	// Retrieve our DEK
	dek, err = mdb.GetDEKUUID("dataKey1")
	if err != nil || dek.Data == nil {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}

	schemaMap := `{
		"bsonType": "object",
		"encryptMetadata": {
			"keyId": [ 
				{
					"$binary": {
						"base64": "` + base64.StdEncoding.EncodeToString(dek.Data) + `",
						"subType": "04"
					}
				}
			],
			"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
		},
		"properties": {
			"name": {
				"bsonType": "object",
				"properties": {
				 	"firstName": {
					 	"encrypt": {
							"bsonType": "string",
							"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
					 	}
				 	},
				 	"lastName": {
						"encrypt": {
							"bsonType": "string",
							"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
						}
					},
					"otherNames": {
				 		"encrypt": {
					 		"bsonType": "string"
				 		}
					}
				}
			},
			"address": {
			 "encrypt": {
				 "bsonType": "object"
			 }
			},
			"dob": {
			 "encrypt": {
				 "bsonType": "date"
			 }
			},
			"phoneNumber": {
			 "encrypt": {
				 "bsonType": "string"
			 }
			},
			"salary": {
			 "encrypt": {
				 "bsonType": "double"
			 }
			},
			"taxIdentifier": {
			 "encrypt": {
				 "bsonType": "string"
			 }
			}
		}
	}`

	// Auto Encryption Client
	var testSchema bson.Raw
	err = bson.UnmarshalExtJSON([]byte(schemaMap), true, &testSchema)
	if err != nil {
		fmt.Printf("Unmarshal Error: %s\n", err)
	}
	completeMap := map[string]interface{}{
		encryptedDB + "." + encryptedColl: testSchema,
	}

	err = mdb.CreateEncryptedClient(completeMap)
	if err != nil {
		fmt.Printf("MDB encrypted client error: %s\n", err)
		exitCode = 1
		return
	}

	// remove the otherNames field if it is nil
	name := payload["name"].(bson.M)
	if name["otherNames"] == nil {
		fmt.Println("Removing nil")
		delete(name, "otherNames")
	}

	result, err = mdb.EncryptedInsertOne(encryptedDB, encryptedColl, payload)
	if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Println(result.InsertedID)

	findResult, err = mdb.EncryptedFindOne(encryptedDB, encryptedColl, bson.M{"_id": result.InsertedID})
	if err != nil {
		fmt.Printf("MongoDB find error: %s\n", err)
		exitCode = 1
		return
	}
	if len(findResult) == 0 {
		fmt.Println("Cannot find document")
		exitCode = 1
		return
	}
	fmt.Printf("%+v\n", findResult)

	// As per the excercise attempt to query salary field
	findResult, err = mdb.EncryptedFindOne(encryptedDB, encryptedColl, bson.M{"salary": 999999.99})
	if err != nil {
		fmt.Printf("MongoDB find error: %s\n", err)
		exitCode = 1
		return
	}
	if len(findResult) == 0 {
		fmt.Println("Cannot find document")
		exitCode = 1
		return
	}
	fmt.Printf("%+v\n", findResult)

	exitCode = 0
}
