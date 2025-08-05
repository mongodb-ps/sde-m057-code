package main

import (
	"C"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/goombaio/namegenerator"
	"go.mongodb.org/mongo-driver/v2/bson"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// NEVER hardcode credentials!
func main() {
	var (
		caFile           = "/data/pki/ca.pem"
		username         = "app_user"
		password         = "SuperP@ssword123!"
		kmipEndpoint     = "kmip-0:5696"
		cryptSharedPath  = "/data/lib/mongo_crypt_v1.so"
		connectionString = "mongodb://mongodb-0:27017/?replicaSet=rs0&tls=true"
		err              error
		exitCode         = 0
		dek              bson.Binary
		findResult       bson.M
		keyVaultColl     = "__keyVault"
		keyVaultDB       = "__encryption"
		kmipTLSConfig    *tls.Config
		result           *mongo.InsertOneResult
		encryptedDB      = "companyData"
		encryptedColl    = "employee"
	)

	defer func() {
		os.Exit(exitCode)
	}()

	providerName := "kmip"
	kmsProvider := map[string]map[string]interface{}{
		providerName: {
			"endpoint": kmipEndpoint,
		},
	}
	cmk := map[string]interface{}{
		"keyId": "1", // this is our CMK ID
	}
	keySpace := keyVaultDB + "." + keyVaultColl

	client, err = createClient(connectionString, username, password, caFile)
	if err != nil {
		fmt.Printf("MDB client error: %s\n", err)
		exitCode = 1
		return
	}

	// Set the KMIP TLS options
	kmsTLSOptions := make(map[string]*tls.Config)
	tlsOptions := map[string]interface{}{
		"tlsCAFile": "/data/pki/ca.pem",
		"tlsCertificateKeyFile": "/data/pki/client-0.pem",
	}
	kmipTLSConfig, err = options.BuildTLSConfig(tlsOptions)
	if err != nil {
		fmt.Printf("Cannot create KMS TLS Config: %s\n", err)
		exitCode = 1
		return
	}
	kmsTLSOptions["kmip"] = kmipTLSConfig
	
	clientEncryption, err = createManualEncryptionClient(client, username, password, caFile, kmsProvider, keySpace, kmsTLSOptions)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	rand.Seed(time.Now().UnixNano())
	id := strconv.Itoa(int(rand.Intn(100000)))

	// get our employee DEK or create
	_, err = getDEK(clientEncryption, id)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			_, err = createDEK(clientEncryption, provider, cmk, id)
			if err != nil {
				fmt.Printf("Cannot create employee DEK: %s\n", err)
				exitCode = 1
				return
			}
		} else {
			fmt.Printf("Cannot get employee DEK: %s\n", err)
			exitCode = 1
			return
		}
	}
	
	firstname, lastname := utils.NameGenerator()
  payload := bson.M{
		"_id": id,
    "name": bson.M{
      "firstName": firstname,
      "lastName": lastname,
      "otherNames": nil,
    },
    "address": bson.M{
      "streetAddress": "29 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz",
    },
    "dob": time.Date(1999, 1, 12, 0, 0, 0, 0, time.Local),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SDSSWN001",
    "role": []string{"Student"},
  }

	// Retrieve our DEK
	dek, err = getDEK(clientEncryption, "dataKey1")
	if err != nil {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}

	db := "companyData"
	collection := "employee"
	
	schemaMap := `{
		"bsonType": "object",
		"encryptMetadata": {
			"keyId": <UPDATE_HERE>,// put your JSON pointer here,
			"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Random"
		},
		"properties": {
			"name": {
				"bsonType": "object",
				"properties": {
					"firstName": {
						"encrypt": {
							"keyId": [ 
								{
									"$binary": {
										"base64": "` + base64.StdEncoding.EncodeToString(<UPDATE_HERE>.Data) + `",
										"subType": "04"
									}
								}
							],
							"bsonType": "string",
							"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"
						 }
					},
					"lastName": {
						"encrypt": {
							"keyId": [ 
								{
									"$binary": {
										"base64": "` + base64.StdEncoding.EncodeToString(<UPDATE_HERE>.Data) + `",
										"subType": "04"
									}
								}
							],
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
		db + "." + collection: testSchema,
	}
	encryptedClient, err = createAutoEncryptionClient(connectionString, keySpace, kmsProvider, kmsTLSOptions, completeMap)
	if err != nil {
		fmt.Printf("MDB encrypted client error: %s\n", err)
		exitCode = 1
		return
	}

	encryptedColl := encryptedClient.Database(db).Collection(collection)

	// remove the otherNames field if it is nil
	name := payload["name"].(bson.M)
	if name["otherNames"] == nil {
		fmt.Println("Removing nil")
		delete(name, "otherNames")
	}

	result, err = encryptedColl.InsertOne(context.TODO(), payload)
	if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Print(result.InsertedID)

	err = encryptedColl.FindOne(context.TODO(), bson.M{"name.firstName": firstname}).Decode(&findResult)
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
