package main

import (
	"C"
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"go.mongodb.org/mongo-driver/v2/mongo/"
	"go.mongodb.org/mongo-driver/v2/mongo//options"
)

func createClient(c string, u string, p string, caFile string) (*mongo.Client, error) {
	//auth setup
	creds := options.Credential{
		Username:      u,
		Password:      p,
		AuthMechanism: "SCRAM-SHA-256",
	}

	// TLS setup
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	// instantiate client
	opts := options.Client().ApplyURI(c).SetAuth(creds).SetTLSConfig(tlsConfig)
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		return nil, err
	}
	err = client.Ping(context.Background(), nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}


func createManualEncryptionClient(c *mongo.Client, kp map[string]map[string]interface{}, kns string, tlsOps map[string]*tls.Config) (*mongo.ClientEncryption, error) {
	o := options.ClientEncryption().SetKeyVaultNamespace(kns).SetKmsProviders(kp).SetTLSConfig(tlsOps)
	client, err := mongo.NewClientEncryption(c, o)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func createAutoEncryptionClient(c string, ns string, kms map[string]map[string]interface{}, tlsOps map[string]*tls.Config, s bson.M) (*mongo.Client, error) {
	extraOptions := map[string]interface{}{
		"cryptSharedLibPath":     "/data/lib/mongo_crypt_v1.so",
		"cryptSharedLibRequired": true,
	}
	autoEncryptionOpts := options.AutoEncryption().
		SetKeyVaultNamespace(ns).
		SetKmsProviders(kms).
		SetSchemaMap(s).
		SetTLSConfig(tlsOps).
		SetExtraOptions(extraOptions)

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(c).SetAutoEncryptionOptions(autoEncryptionOpts))

	if err != nil {
		return nil, err
	}

	return client, nil
}

func encryptManual(ce *mongo.ClientEncryption, dek Binary, alg string, data interface{}) (Binary, error) {
	var out Binary
	rawValueType, rawValueData, err := bson.MarshalValue(data)
	if err != nil {
		return Binary{}, err
	}

	rawValue := bson.RawValue{Type: rawValueType, Value: rawValueData}

	encryptionOpts := options.Encrypt().
		SetAlgorithm(alg).
		SetKeyID(dek)

	out, err = ce.Encrypt(context.TODO(), rawValue, encryptionOpts)
	if err != nil {
		return Binary{}, err
	}

	return out, nil
}

func main() {
	var (
		keyVaultDB 			 = "__encryption"
		keyVaultColl 		 = "__keyVault"
		keySpace         = keyVaultDB + "." + keyVaultColl
		caFile			 			= "/data/pki/ca.pem"
		username 		 			= "app_user"
		password		 			= <UPDATE_HERE>
		connectionString 	= "mongodb://mongodb-0:27017/?replicaSet=rs0&tls=true"
		clientEncryption *mongo.ClientEncryption
		encryptedClient  *mongo.Client
		client           *mongo.Client
		exitCode         = 0
		result           *mongo.InsertOneResult
		dekFindResult    bson.M
		findResult			 bson.M
		dek              Binary
		encryptedName		Binary
		kmipTLSConfig    *tls.Config
		err							 error
	)

	defer func() {
		os.Exit(exitCode)
	}()

	provider := "kmip"
	kmsProvider := map[string]map[string]interface{}{
		provider: {
			"endpoint": <UPDATE_HERE>
		},
	}

	client, err = createClient(connectionString, username, password, caFile)
	if err != nil {
		fmt.Printf("MDB client error: %s\n", err)
		exitCode = 1
		return
	}

	coll := client.Database("__encryption").Collection("__keyVault")

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
	

	clientEncryption, err = createManualEncryptionClient(client, kmsProvider, keySpace, kmsTLSOptions)
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	// Auto Encryption Client
	encryptedClient, err = createAutoEncryptionClient(connectionString, keySpace, kmsProvider, kmsTLSOptions, bson.M{})
	if err != nil {
		fmt.Printf("MDB encrypted client error: %s\n", err)
		exitCode = 1
		return
	}

	encryptedColl := encryptedClient.Database("companyData").Collection("employee")
	
  payload := bson.M{
    "name": bson.M{
      "firstName": "Poorna",
      "lastName": "Muggle",
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
    "role": []string{"CE"},
  }

	// Retrieve our DEK
	opts := options.FindOne().SetProjection(bson.D{{Key: "_id", Value: 1}})
	err = coll.FindOne(context.TODO(), bson.D{{Key: "keyAltNames", Value: "dataKey1"}}, opts).Decode(&dekFindResult)
	if err != nil || len(dekFindResult) == 0 {
		fmt.Printf("DEK find error: %s\n", err)
		exitCode = 1
		return
	}
	dek = dekFindResult["_id"].(Binary)

	// remove the otherNames field if it is nil
	name := payload["name"].(bson.M)
	if name["otherNames"] == nil {
		fmt.Println("Removing nil")
		delete(name, "otherNames")
	} else {
		name["otherNames"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", name["otherNames"])
		if err != nil {
			fmt.Printf("ClientEncrypt error: %s\n", err)
			exitCode = 1
			return
		}
	}

	name["firstName"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", name["firstName"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	name["lastName"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", name["lastName"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}
	payload["name"] = name

	payload["address"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["address"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["dob"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["dob"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["phoneNumber"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["phoneNumber"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["salary"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["salary"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	payload["taxIdentifier"], err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Random", payload["taxIdentifier"])
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	coll = client.Database("companyData").Collection("employee")

	result, err = coll.InsertOne(context.TODO(), payload)
	if err != nil {
		fmt.Printf("Insert error: %s\n", err)
		exitCode = 1
		return
	}
	fmt.Print(result.InsertedID)


	encryptedName, err = encryptManual(clientEncryption, dek, "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic", "Poorna")
	if err != nil {
		fmt.Printf("ClientEncrypt error: %s\n", err)
		exitCode = 1
		return
	}

	// WRITE YOUR QUERY HERE FOR AUTODECRYPTION. REMEMBER WHICH CLIENT TO USE!
	err = <UPDATE_HERE> 
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
