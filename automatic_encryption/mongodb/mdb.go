package mdb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MDBType struct {
	client                *mongo.Client
	clientEncryption      *mongo.ClientEncryption
	encryptedClient       *mongo.Client
	connectionString      string
	username              string
	password              string
	caFile                string
	keyProvider           map[string]map[string]interface{}
	keyVaultNameSpace     string
	keyProviderTLSOptions map[string]*tls.Config
	cryptSharedPath       string
	ctx                   context.Context
}

func NewMDB(
	c string,
	u string,
	p string,
	caFile string,
	kp map[string]map[string]interface{},
	kns string,
	tlsOps map[string]*tls.Config,
	csp string,
) (*MDBType, error) {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
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
		cryptSharedPath:       csp,
		ctx:                   ctx,
	}
	var o *options.AutoEncryptionOptions

	err := mdb.createClient(o)
	if err != nil {
		return nil, err
	}
	return &mdb, nil
}

func (m *MDBType) createClient(autoEncryptionOpts *options.AutoEncryptionOptions) error {
	var opts *options.ClientOptions
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
	if autoEncryptionOpts == nil {
		opts = options.Client().ApplyURI(m.connectionString).SetAuth(creds).SetTLSConfig(tlsConfig)
		m.client, err = mongo.Connect(opts)
		if err != nil {
			return err
		}
		/*defer func() {
			if err = m.client.Disconnect(m.ctx); err != nil {
				log.Panic(err)
			}
		}()*/
		err = m.client.Ping(context.Background(), nil)
		if err != nil {
			return err
		}
	} else {
		opts = options.Client().ApplyURI(m.connectionString).SetAuth(creds).SetTLSConfig(tlsConfig).SetAutoEncryptionOptions(autoEncryptionOpts)
		m.encryptedClient, err = mongo.Connect(opts)
		if err != nil {
			return err
		}
		/*defer func() {
			if err = m.encryptedClient.Disconnect(m.ctx); err != nil {
				log.Panic(err)
			}
		}()*/
		err = m.encryptedClient.Ping(context.Background(), nil)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *MDBType) CreateEncryptedClient(schema map[string]interface{}) error {

	autoEncryptionOpts := options.AutoEncryptionOptions{
		KeyVaultNamespace: m.keyVaultNameSpace,
		KmsProviders:      m.keyProvider,
		SchemaMap:         schema,
		TLSConfig:         m.keyProviderTLSOptions,
		ExtraOptions:      map[string]interface{}{"mongocryptdSpawnPath": m.cryptSharedPath},
	}

	err := m.createClient(&autoEncryptionOpts)
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

	out, err = m.clientEncryption.Encrypt(context.TODO(), rawValue, encryptionOpts)
	if err != nil {
		return bson.Binary{}, err
	}

	return out, nil
}

// function to perform manual decryption of a document with the ClientEncryption instance
func (m *MDBType) DecryptManual(d bson.M) (bson.M, error) {
	return m.traverseBson(d)
}

// function to decrypt a single value with the ClientEncryption instance
func (m *MDBType) DecryptField(d bson.Binary) (bson.RawValue, error) {
	out, err := m.clientEncryption.Decrypt(context.TODO(), d)
	if err != nil {
		return bson.RawValue{}, err
	}

	return out, nil
}

// Function that traverses a BSON object and determines if the type is a primitive,
// if so, we check if this is a bson.Binary subtype 6 and then call the manual decrypt function
// to decrypt the value. We call the same function if arrays or subdocuments are found
func (m *MDBType) traverseBson(d bson.M) (bson.M, error) {
	for k, v := range d {
		a, ok := v.(bson.M)
		if ok {
			data, err := m.traverseBson(a)
			if err != nil {
				return bson.M{}, err
			}
			d[k] = data
		} else {
			// Check if bson.Binary Subtype 6 data, e.g. encrypted. Skip if it is not
			i, ok := v.(bson.Binary)
			if !ok {
				// not bson.Binary data
				continue
			}
			if i.Subtype == 6 {
				data, err := m.DecryptField(i)
				if err != nil {
					return bson.M{}, err
				}
				d[k] = data
			}
		}
	}
	return d, nil
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

func (m *MDBType) EncryptedInsertOne(db string, coll string, data interface{}) (*mongo.InsertOneResult, error) {
	c := m.encryptedClient.Database(db).Collection(coll)
	result, err := c.<UPDATE_HERE>
	if err != nil {
		return nil, err
	}

	return result, nil
}
