package main

import (
	"C"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	mdb "sde/csfle/mongodb"
	"sde/csfle/utils"

	"go.mongodb.org/mongo-driver/v2/bson"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func main() {
	var (
		keyVaultDB       = "__encryption"
		keyVaultColl     = "__keyVault"
		kmipEndpoint 		 = <UPDATE_HERE>
		keySpace         = keyVaultDB + "." + keyVaultColl
		caFile           = <UPDATE_HERE>
		keyCertFile      = <UPDATE_HERE>
		username         = <UPDATE_HERE>
		password         = <UPDATE_HERE>
		connectionString = "mongodb://mongodb-0:27017/?replicaSet=rs0&tls=true"
		exitCode         = 0
		kmipTLSConfig    *tls.Config
		result           *mongo.InsertOneResult
		dek              bson.Binary
		encryptedName    bson.Binary
		findResult       bson.M
		outputData       bson.M
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

	mdb, err := mdb.NewMDB(connectionString, username, password, caFile, kmsProvider, keySpace, kmsTLSOptions)
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

	payload := bson.M{
		"name": bson.M{
			"firstName":  "Manish",
			"lastName":   "Engineer",
			"otherNames": nil,
		},
		"address": bson.M{
			"streetAddress": "12 Bson Street",
			"suburbCounty":  "Mongoville",
			"stateProvince": "Victoria",
			"zipPostcode":   "3999",
			"country":       "Oz",
		},
		"dob":           time.Date(1981, 11, 11, 0, 0, 0, 0, time.Local),
		"phoneNumber":   "1800MONGO",
		"salary":        999999.99,
		"taxIdentifier": "78SDSSNN001",
		"role":          []string{"DEV"},
	}

	// Retrieve our DEK or fail if missing
	dek, err = mdb.GetDEKUUID("dataKey1")
	if err != nil || dek.Data == nil {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}

	detFields := []string{"name.firstName", "name.lastName"}
	randFields := []string{"address", "dob", "phoneNumber", "salary", "taxIdentifier"}
	allEncryptedFields := append(detFields, randFields...)

	// Encrypt the payload
	for _, field := range detFields {
		tempVal, err := mdb.EncryptField(dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", utils.GetField(payload, field))
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
		utils.SetField(payload, field, tempVal)
	}

	for _, field := range randFields {
		tempVal, err := mdb.EncryptField(dek, <UPDATE_HERE>, utils.GetField(payload, field))
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
		utils.SetField(payload, field, tempVal)
	}

	// remove the otherNames field if it is nil or encrypted
	middleName := utils.GetField(payload, "name.otherNames")
	if middleName != nil {
		tempVal, err := mdb.EncryptField(dek, <UPDATE_HERE>, middleName)
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
		utils.SetField(payload, "name.otherNames", tempVal)
	} else {
		utils.DeleteField(payload, "name.otherNames")
	}

	// test to see if all our fields are encrypted:
	for _, field := range allEncryptedFields {
		if !utils.TestEncrypted(utils.GetField(payload, field)) {
			fmt.Printf("Field %s is not encrypted\n", field)
			exitCode = 1
			return
		}
	}

	result, err = mdb.InsertOne(encryptedDB, encryptedColl, payload)
	if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Print(result.InsertedID)

	exitCode = 0
}
