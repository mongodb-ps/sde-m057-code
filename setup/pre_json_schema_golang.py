try:
  from os import path
  from sys import version_info
  from bson.binary import STANDARD, Binary
  from bson.codec_options import CodecOptions
  from datetime import datetime
  from pymongo import MongoClient
  from pymongo.encryption import Algorithm
  from pymongo.encryption import ClientEncryption
  from pymongo.errors import EncryptionError, ServerSelectionTimeoutError, ConnectionFailure
  from urllib.parse import quote_plus
  import sys
except ImportError as e:
  from os import path
  print(f"Import error for {path.basename(__file__)}: {e}")
  exit(1)



# PUT VALUES HERE!

MDB_PASSWORD = "SuperP@ssword123!"
APP_USER = "app_user"
SDE_PASSWORD = "s3cr3t!"
SDE_USER = "sdeadmin"
CA_PATH = "/data/pki/ca.pem"

def check_python_version() -> str | None:
  """Checks if the current Python version is supported.

  Returns:
    A string indicating that the current Python version is not supported, or None if the current Python version is supported.
  """
  if version_info.major < 3 or (version_info.major == 3 and version_info.minor < 10):
    return f"Python version {version_info.major}.{version_info.minor} is not supported, please use 3.10 or higher"
  return None

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
    client = MongoClient(connection_string)
    client.admin.command('hello')
    return client, None
  except (ServerSelectionTimeoutError, ConnectionFailure) as e:
    return None, f"Cannot connect to database, please check settings in config file: {e}"

def decrypt_data(client_encryption, data):
  """ Returns a decrypted value if the input is encrypted, or returns the input value

  Tests the input value to determine if it is a BSON binary subtype 6 (aka encrypted data).
  If true, the value is decrypted. If false the input value is returned

  Parameters
  -----------
    client_encryption: mongo.ClientEncryption
      Instantiated mongo.ClientEncryption instancesection
    data: value
      A value to be tested, and decrypted if required
  Return
  -----------
    data/unencrypted_data: value
      unencrypted or input value
  """

  try:
    if type(data) == Binary and data.subtype == 6:

      decrypted_data = client_encryption.decrypt(data)

      return decrypted_data
    else:
      return data
  except EncryptionError as e:
    raise e

def traverse_bson(client_encryption: ClientEncryption, data: dict) -> dict | str:
  """ Iterates over a object/value and determines if the value is a scalar or document
  
  Tests the input value is a list or dictionary, if not calls the `decrypt_data` function, if
  true it calls itself with the value as the input. 

  Parameters
  -----------
    client_encryption: mongo.ClientEncryption
      Instantiated mongo.ClientEncryption instance
    data: value
      A value to be tested, and decrypted if required
  Return
  -----------
    data/unencrypted_data: value
      unencrypted or input value
  """
  
  if isinstance(data, list):
    return [traverse_bson(client_encryption, v) for v in data]
  elif isinstance(data, dict):
    return {k: traverse_bson(client_encryption, v) for k, v in data.items()}
  else:
    return decrypt_data(client_encryption, data)
  
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

  # check version of Python is correct
  err = check_python_version()
  if err is not None:
    print(err)
    exit(1)

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
  encrypted_coll_name = "employee"

  # instantiate our MongoDB Client object
  client, err = mdb_client(connection_string)
  if err is not None:
    print(err)
    sys.exit(1)

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
  client.admin.command("createUser", APP_USER, pwd=MDB_PASSWORD, roles=["cryptoClient", {"role": "readWrite", "db": "companyData"}])

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

  payload = {
    "name": {
      "firstName": "Kuber",
      "lastName": "Engineer",
      "otherNames": None,
    },
    "address": {
      "streetAddress": "12 Bson Street",
      "suburbCounty": "Mongoville",
      "stateProvince": "Victoria",
      "zipPostcode": "3999",
      "country": "Oz"
    },
    "dob": datetime(1981, 11, 11),
    "phoneNumber": "1800MONGO",
    "salary": 999999.99,
    "taxIdentifier": "78SDSSNN001",
    "role": [
      "DEV"
    ]
  }

  try:

    # Retrieve the DEK UUID
    data_key_id_1 = client_encryption.get_key_by_alt_name("dataKey1")
    if data_key_id_1 is None:
      data_key_id_1, err = make_dek(client_encryption, "dataKey1", provider, "1")
      if err is not None:
        print("Failed to find DEK")
        sys.exit()
    else:
      data_key_id_1 = data_key_id_1["_id"]

    # Do deterministic fields
    payload["name"]["firstName"] = client_encryption.encrypt(payload["name"]["firstName"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, data_key_id_1)
    payload["name"]["lastName"] = client_encryption.encrypt(payload["name"]["lastName"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, data_key_id_1)

    # Do random fields
    if payload["name"]["otherNames"] is None:
      del(payload["name"]["otherNames"])
    else:
      payload["name"]["otherNames"] = client_encryption.encrypt(payload["name"]["otherNames"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["address"] = client_encryption.encrypt(payload["address"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["dob"] = client_encryption.encrypt(payload["dob"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["phoneNumber"] = client_encryption.encrypt(payload["phoneNumber"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["salary"] = client_encryption.encrypt(payload["salary"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)
    payload["taxIdentifier"] = client_encryption.encrypt(payload["taxIdentifier"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, data_key_id_1)

    # Test if the data is encrypted
    for data in [ payload["name"]["firstName"], payload["name"]["lastName"], payload["address"], payload["dob"], payload["phoneNumber"], payload["salary"], payload["taxIdentifier"]]:
      if type(data) is not Binary or data.subtype != 6:
        print("Data is not encrypted")
        sys.exit()

    if "otherNames" in payload["name"] and payload["name"]["otherNames"] is None:
      print("None cannot be encrypted")
      sys.exit(-1)

    result = client[encrypted_db_name][encrypted_coll_name].insert_one(payload)

    print(result.inserted_id)

  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit()


  try:

    encrypted_name = client_encryption.encrypt("Kuber", Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, data_key_id_1)
    encrypted_doc = client[encrypted_db_name][encrypted_coll_name].find_one({"name.firstName": encrypted_name})
    print(encrypted_doc)

    decrypted_doc = traverse_bson(client_encryption, encrypted_doc)
    print(decrypted_doc)

  except EncryptionError as e:
    print(f"Encryption error: {e}")
    sys.exit()



if __name__ == "__main__":
  main()