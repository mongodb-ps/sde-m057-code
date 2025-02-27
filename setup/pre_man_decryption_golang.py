try:
  from os import path
  from bson.binary import STANDARD
  from bson.codec_options import CodecOptions
  from pymongo import MongoClient
  from pymongo.encryption import ClientEncryption
  from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure, OperationFailure
  import sys
  from urllib.parse import quote_plus
except ImportError as e:
  from os import path
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)

MDB_PASSWORD = "SuperP@ssword123!"
APP_USER = "app_user"
SDE_PASSWORD = "s3cr3t!"
SDE_USER = "sdeadmin"
CA_PATH = "/data/pki/ca.pem"

def mdb_client(connection_string: str, auto_encryption_opts: tuple[dict | None] = None) -> tuple[MongoClient | None, str | None]:
  """ Returns a MongoDB client instance
  
  Creates a  MongoDB client instance and tests the client via a `hello` to the server
  
  Parameters
  ------------
    connection_string: string
      MongoDB connection string URI containing username, password, host, port, tls, etc
  Return
  ------------
    client: mongo.MongoClient
      MongoDB client instance
    err: error
      Error message or None of successful
  """

  try:
    client = MongoClient(connection_string, auto_encryption_opts=auto_encryption_opts)
    client.admin.command('hello')
    return client, None
  except (ServerSelectionTimeoutError, ConnectionFailure) as e:
    return None, f"Cannot connect to database, please check settings in config file: {e}"


def make_dek(client: MongoClient, altName: str, provider_name: str, keyId: str) -> tuple[str | None, str | None]:
  """ Return a DEK's UUID for a give KeyAltName. Creates a new DEK if the DEK is not found.
  
  Queries a key vault for a particular KeyAltName and returns the UUID of the DEK, if found.
  If not found, the UUID and Key Provider object and CMK ID are used to create a new DEK

  Parameters
  -----------
    client: mongo.ClientEncryption
      An instantiated ClientEncryption instance that has access to the key vault
    altName: string
      The KeyAltName of the UUID to find
    provider_name: string
      The name of the key provider. "aws", "gcp", "azure", "kmip", or "local"
    keyId: string
      The key ID for the Customer Master Key (CMK)
  Return
  -----------
    employee_key_id: UUID
      The UUID of the DEK
    error: error
      Error message or None of successful
  """
  
  employee_key_id = client.get_key_by_alt_name(str(altName))
  if employee_key_id == None:
    try:
      master_key = {"keyId": keyId, "endpoint": "kmip-0:5696"}
      employee_key_id = client.create_data_key(kms_provider=provider_name, master_key=master_key, key_alt_names=[str(altName)])
    except EncryptionError as e:
      return None, f"ClientEncryption error: {e}"
  else:
    employee_key_id = employee_key_id["_id"]
  return employee_key_id, None

def main():
  # Obviously this should not be hardcoded
  connection_string = "mongodb://%s:%s@mongodb-0:27017/?serverSelectionTimeoutMS=5000&tls=true&tlsCAFile=%s" % (
    quote_plus(SDE_USER),
    quote_plus(SDE_PASSWORD),
    quote_plus(CA_PATH)
  )

  # Declare or key vault namespce
  keyvault_db = "__encryption"
  keyvault_coll = "__keyVault"
  keyvault_namespace = f"{keyvault_db}.{keyvault_coll}"

  # declare our key provider type
  provider = "kmip"

  # declare our key provider attributes
  kms_provider_details = {
    provider: {
      "endpoint": "kmip-0:5696"
    }
  }
  
  # declare our database and collection
  encrypted_db_name = "companyData"

  try:
    # instantiate our MongoDB Client object
    client, err = mdb_client(connection_string)
    if err is not None:
      print(err)
      sys.exit(1)

    db = client[keyvault_db]
    coll = db[keyvault_coll]

    # Create role and user
    client.admin.command("createRole", "cryptoClient",  privileges=[
      {
          "resource": {
            "db": keyvault_db,
            "collection": keyvault_coll
          },
          "actions": [ "find" ],
        }
      ],
      roles=[]
    )
  except OperationFailure as e:
    if e.code == 51002:
      print("Role already exists")
    else:
      print(f"Error creating role: {e}")
      sys.exit()

  try:
    client.admin.command("createUser", APP_USER, pwd=MDB_PASSWORD, roles=["cryptoClient", {"role": "readWrite", "db": encrypted_db_name}])
  except OperationFailure as e:
    if e.code == 51003:
      print("Role already exists")
    else:
      print(f"Error creating role: {e}")
      sys.exit()

  client["__encryption"]["__keyVault"].create_index("keyAltNames", unique=True, partialFilterExpression={
    	"keyAltNames": {
      	"$exists": True
      }})
  
  # Instantiate our ClientEncryption object
  client_encryption = ClientEncryption(
    kms_provider_details,
    keyvault_namespace,
    client,
    CodecOptions(uuid_representation=STANDARD),
    kms_tls_options = {
      "kmip": {
        "tlsCAFile": "/data/pki/ca.pem",
        "tlsCertificateKeyFile": "/data/pki/server.pem"
      }
    }
  )

  # Retrieve the DEK UUID
  data_key_id_1 = client_encryption.get_key_by_alt_name("dataKey1")
  if data_key_id_1 is None:
    data_key_id_1, err = make_dek(client_encryption, "dataKey1", provider, "1")
    if err is not None:
      print("Failed to find DEK")
      sys.exit()
  else:
    data_key_id_1 = data_key_id_1["_id"]

if __name__ == "__main__":
  main()
