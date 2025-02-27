package mdb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"go.mongodb.org/mongo-driver/v2/bson"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MDBType struct {
	client                *mongo.Client
	clientEncryption      *mongo.ClientEncryption
	connectionString      string
	username              string
	password              string
	caFile                string
	keyProvider           map[string]map[string]interface{}
	keyVaultNameSpace     string
	keyProviderTLSOptions map[string]*tls.Config
}

func NewMDB(
	c string,
	u string,
	p string,
	caFile string,
	kp map[string]map[string]interface{},
	kns string,
	tlsOps map[string]*tls.Config,
) (*MDBType, error) {
	var err error
	mdb := MDBType{
		client:                nil,
		clientEncryption:      nil,
		connectionString:      c,
		username:              u,
		password:              p,
		caFile:                caFile,
		keyProvider:           kp,
		keyVaultNameSpace:     kns,
		keyProviderTLSOptions: tlsOps,
	}

	err = mdb.createClient()
	if err != nil {
		return nil, err
	}
	return &mdb, nil
}

func (m *MDBType) createClient() error {
	//auth setup
	creds := options.Credential{
		Username:      m.username,
		Password:      m.password,
		AuthMechanism: "SCRAM-SHA-256",
	}

	// TLS setup
	caCert, err := os.ReadFile(m.caFile)
	if err != nil {
		return err
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return fmt.Errorf("failed to append CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	// instantiate client
	opts := options.Client().ApplyURI(m.connectionString).SetAuth(creds).SetTLSConfig(tlsConfig)
	m.client, err = mongo.Connect(opts)
	if err != nil {
		return err
	}
	err = m.client.Ping(context.Background(), nil)
	if err != nil {
		return err
	}

	return nil
}

// Function to create the MognoDB ClientEncryption instance
func (m *MDBType) CreateManualEncryptionClient() error {
	var err error
	o := options.ClientEncryption().SetKeyVaultNamespace(m.keyVaultNameSpace).SetKmsProviders(m.keyProvider).SetTLSConfig(m.keyProviderTLSOptions)
	m.clientEncryption, err = mongo.NewClientEncryption(m.client, o)
	if err != nil {
		return err
	}

	return nil
}

// Function to perform the manual encryption with the ClientEncryption instance
func (m *MDBType) EncryptField(dek bson.Binary, alg string, data interface{}) (bson.Binary, error) {
	var out bson.Binary
	rawValueType, rawValueData, err := bson.MarshalValue(data)
	if err != nil {
		return bson.Binary{}, err
	}

	rawValue := bson.RawValue{Type: rawValueType, Value: rawValueData}

	encryptionOpts := options.Encrypt().
		SetAlgorithm(alg).
		SetKeyID(dek)

	out, err = m.clientEncryption.<UPDATE_HERE>(context.TODO(), rawValue, encryptionOpts)
	if err != nil {
		return bson.Binary{}, err
	}

	return out, nil
}

func (m *MDBType) GetDEKUUID(dek string) (bson.Binary, error) {
	var dekFindResult bson.M
	err := m.clientEncryption.GetKeyByAltName(context.Background(), dek).Decode(&dekFindResult)
	if err != nil {
		return bson.Binary{}, err
	}
	if len(dekFindResult) == 0 {
		return bson.Binary{}, nil
	}
	b, ok := dekFindResult["_id"].(bson.Binary)
	if !ok {
		return bson.Binary{}, errors.New("DEK conversion error")
	}
	return b, nil
}

func (m *MDBType) InsertOne(db string, coll string, data interface{}) (*mongo.InsertOneResult, error) {
	c := m.client.Database(db).Collection(coll)
	result, err := c.InsertOne(context.TODO(), data)
	if err != nil {
		return nil, err
	}

	return result, nil
}
