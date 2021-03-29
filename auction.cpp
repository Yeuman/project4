#include "shim.h"
#include<map>
#include "logging.h"
#include <string>
#include <ctime>
#include <cstring>
#include <stdio.h>
#include <cstdlib>
#include <math.h>
#include <random>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "sgx_utils.h"

#define OK "OK"
#define NOT_FOUND "Bid not found"
#define RSA_MOD_SIZE 256 //hardcode n size to be 384
#define RSA_E_SIZE 4 //hardcode e size to be 4

#define MAX_VALUE_SIZE 1024
int user_count = 0;
std::map<int, std::string> usernames;
std::map<std::string, std::string> userPublicKeys;
void *chaincode_public_key = NULL;
void *chaincode_private_key = NULL;
unsigned char *user_encrypted_data;
std::string testVariable;

std::string putTestVariable(std::string a, shim_ctx_ptr_t ctx)
{
	testVariable = a;
	return testVariable;
}

std::string getTestVariable(shim_ctx_ptr_t ctx)
{
        return testVariable;
}

//Will store the public key and return private key for user
std::string  createUserPublicPrivateKey(std::string user_name, shim_ctx_ptr_t ctx)	
{
	
	void *public_key = NULL;
	void *private_key = NULL;
	
	unsigned char p_n[256], p_d[256], p_p[256], p_q[256], p_dmp1[256], p_dmq1[256], p_iqmp[256]; 
	long p_e = 65537;

	std::string s = "Test";

	if (sgx_create_rsa_key_pair(RSA_MOD_SIZE, sizeof(p_e), p_n, p_d, (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp) == SGX_SUCCESS){ 
		s = s + "Created key pair";
	}

	if(sgx_create_rsa_pub1_key(RSA_MOD_SIZE, sizeof(p_e), p_n, (unsigned char*)&p_e, &public_key) == SGX_SUCCESS) {
		s = s + "Reached Public Key phase";
	}

	if(sgx_create_rsa_priv2_key(RSA_MOD_SIZE, sizeof(p_e), (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp, &private_key) == SGX_SUCCESS) {
		s = s + "Reached Private Key phase";
	}
	
	std::string *pk = static_cast<std::string*>(public_key);
	std::string pubKey = *pk;
	userPublicKeys[user_name] = pubKey;
	delete pk;

	std::string *privk = static_cast<std::string*>(private_key);
        std::string privKey = *privk;
        delete privk;

	return privKey;
}

// To be called once at the beginning. Creates chaincode public private key.
std::string  createChaincodePublicPrivateKey(shim_ctx_ptr_t ctx)	
{
	unsigned char p_n[256], p_d[256], p_p[256], p_q[256], p_dmp1[256], p_dmq1[256], p_iqmp[256]; 
	long p_e = 65537;

	std::string s = "Test";

	if (sgx_create_rsa_key_pair(RSA_MOD_SIZE, sizeof(p_e), p_n, p_d, (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp) == SGX_SUCCESS){ 
		s = s + "Created key pair";
	}

	if(sgx_create_rsa_pub1_key(RSA_MOD_SIZE, sizeof(p_e), p_n, (unsigned char*)&p_e, &chaincode_public_key) == SGX_SUCCESS) {
		s = s + "Reached Public Key phase";
	}

	if(sgx_create_rsa_priv2_key(RSA_MOD_SIZE, sizeof(p_e), (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp, &chaincode_private_key) == SGX_SUCCESS) {
		s = s + "Reached Private Key phase";
	}
	return s;
}

// To be called to retrieve the chaincode public key
std::string  retrieveChaincodePublicKey(shim_ctx_ptr_t ctx)	
{
	std::string *pk = static_cast<std::string*>(chaincode_public_key);
        std::string pubKey = *pk;
        delete pk;

	return pubKey;
}

//Example signing simulation
std::string signingSimulation(shim_ctx_ptr_t ctx)
{
	unsigned char p_n[384], p_d[384], p_p[384], p_q[384], p_dmp1[384], p_dmq1[384], p_iqmp[384];
	long p_e = 65537;
	sgx_rsa3072_signature_t p_signature[384];

	std::string str = "Hello, world";

	//uint8_t* p_data = reinterpret_cast<uint8_t*>(str.c_str());

	const uint8_t p_data[] = "Hello world";

	std::string s = "Test";
	if (sgx_create_rsa_key_pair(384, sizeof(p_e), p_n, p_d, (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp) == SGX_SUCCESS){
                s = s + "Created key pair";
        }

	sgx_rsa3072_key_t rsa_key;
	memcpy(&(rsa_key.mod), &(p_n), sizeof(rsa_key.mod));
	memcpy(&(rsa_key.d), &(p_d), sizeof(rsa_key.d));
	memcpy(&(rsa_key.e), &(p_e), sizeof(rsa_key.e));

	if (sgx_rsa3072_sign(p_data, sizeof(p_data), &rsa_key, p_signature) == SGX_SUCCESS) {
		s = s + "Signed data";
	}

	sgx_rsa3072_public_key_t temp_public_key;
	memcpy(&(temp_public_key.mod), &(p_n), sizeof(temp_public_key.mod));
	memcpy(&(temp_public_key.exp), &(p_e), sizeof(temp_public_key.exp));
	
	sgx_rsa_result_t verify_result = SGX_RSA_INVALID_SIGNATURE;
	
	if (sgx_rsa3072_verify(p_data, sizeof(p_data), &temp_public_key, p_signature, &verify_result) == SGX_SUCCESS){
		s = s + "Verified signature";	
	}
	
	if (sgx_rsa3072_verify(p_data, sizeof(p_data), &temp_public_key, p_signature, &verify_result) == SGX_ERROR_INVALID_PARAMETER){
		s = s + "error invalid parameter";	
	}
	
	if (sgx_rsa3072_verify(p_data, sizeof(p_data), &temp_public_key, p_signature, &verify_result) == SGX_RSA_INVALID_SIGNATURE){
		s = s + "error invalid signature";	
	}
	
	if (sgx_rsa3072_verify(p_data, sizeof(p_data), &temp_public_key, p_signature, &verify_result) == SGX_ERROR_OUT_OF_MEMORY){
		s = s + "error out of memory";	
	}
	
	if (sgx_rsa3072_verify(p_data, sizeof(p_data), &temp_public_key, p_signature, &verify_result) == SGX_ERROR_UNEXPECTED){
		s = s + "error unexpected";	
	}
	
	if (verify_result != SGX_RSA_VALID)
    	{
        	s = s + "Invalid Result";
    	}

	return s;
}

//Example encryption simulation
std::string  encryptionSimulation(shim_ctx_ptr_t ctx)
{
	void *public_key = NULL;
	void *private_key = NULL;
	
	unsigned char p_n[256], p_d[256], p_p[256], p_q[256], p_dmp1[256], p_dmq1[256], p_iqmp[256]; 
	long p_e = 65537;

	std::string s = "Test";

	if (sgx_create_rsa_key_pair(RSA_MOD_SIZE, sizeof(p_e), p_n, p_d, (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp) == SGX_SUCCESS){ 
		s = s + "Created key pair";
	}

	if(sgx_create_rsa_pub1_key(RSA_MOD_SIZE, sizeof(p_e), p_n, (unsigned char*)&p_e, &public_key) == SGX_SUCCESS) {
		s = s + "Reached Public Key phase";
	}

	if(sgx_create_rsa_priv2_key(RSA_MOD_SIZE, sizeof(p_e), (unsigned char*)&p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp, &private_key) == SGX_SUCCESS) {
		s = s + "Reached Private Key phase";
	}	

	size_t pout_len = 0;

	char * pin_data = "Hello World!";

	if(sgx_rsa_pub_encrypt_sha256(public_key, NULL, &pout_len, (unsigned char *)pin_data, strlen(pin_data)) == SGX_SUCCESS) {
		s = s + "Encrypted";
	}

	unsigned char pout_data[pout_len];

	if(sgx_rsa_pub_encrypt_sha256(public_key, pout_data, &pout_len, (unsigned char *)pin_data, strlen(pin_data)) == SGX_SUCCESS) {
                s = s + "Encrypted Part 2";
        }

	size_t decrypted_len = 0;

	if(sgx_rsa_priv_decrypt_sha256(private_key, NULL, &decrypted_len, pout_data, sizeof(pout_data)) == SGX_SUCCESS) {
		s = s + "Decrypted";
	}

	unsigned char decrypted_pout_data[decrypted_len];

	if(sgx_rsa_priv_decrypt_sha256(private_key, decrypted_pout_data, &decrypted_len, pout_data, sizeof(pout_data)) == SGX_SUCCESS) {
                s = s + "Decrypted Part 2";
        }

	int c = 0;
	while(decrypted_pout_data[c] != NULL) {
		s.append(1, decrypted_pout_data[c]);
		++c;
	}

	return s;
}

std::string decryptAndStoreBid(std::string user_name, std::string pin_data, shim_ctx_ptr_t ctx) {
	//Placeholder for pin_data
	//char data[pin_data.length()];

	//int i;
        //for (i = 0; i < sizeof(data); i++) {
        //        data[i] = pin_data[i];
        //}
	//unsigned char* encrypted_data = reinterpret_cast<unsigned char*>(data);
	
	size_t decrypted_len = 0;

	std::string s = "Test";

	if(sgx_rsa_priv_decrypt_sha256(chaincode_private_key, NULL, &decrypted_len, user_encrypted_data, sizeof(user_encrypted_data)) == SGX_SUCCESS) {
		s = s + "Decrypted";
	}

	unsigned char decrypted_pout_data[decrypted_len];

	if(sgx_rsa_priv_decrypt_sha256(chaincode_private_key, decrypted_pout_data, &decrypted_len, user_encrypted_data, sizeof(user_encrypted_data)) == SGX_SUCCESS) {
        	s = s + "Decrypted Part 2";
	}
	
	std::string auction_bid = "";
	int x = 0;
	while(decrypted_pout_data[x] != NULL) {
                auction_bid.append(1, decrypted_pout_data[x]);
                ++x;
        }
	put_state(user_name.c_str(), (uint8_t*)auction_bid.c_str(), auction_bid.size(), ctx);
	usernames[user_count] = user_name;
	user_count++;
	int c = 0;
        while(decrypted_pout_data[c] != NULL) {
                s.append(1, decrypted_pout_data[c]);
                ++c;
	}
	return s;
}

// Function to encrypt the bid for the user
std::string encrypter(std::string pin_data, shim_ctx_ptr_t ctx) {

	char data_to_encrypt[pin_data.length()];

	int i;
	for (i = 0; i < sizeof(data_to_encrypt); i++) {
        	data_to_encrypt[i] = pin_data[i];
    	}
	size_t pout_len = 0;

	std::string s = "Test";

	if(sgx_rsa_pub_encrypt_sha256(chaincode_public_key, NULL, &pout_len, (unsigned char *)data_to_encrypt, strlen(data_to_encrypt)) == SGX_SUCCESS) {
		s = s + "Encrypted";
	}

	unsigned char pout_data[pout_len];
	
        if(sgx_rsa_pub_encrypt_sha256(chaincode_public_key, pout_data, &pout_len, (unsigned char *)data_to_encrypt, strlen(data_to_encrypt)) == SGX_SUCCESS) {
                s = s + "Encrypted Part 2";
        }

	user_encrypted_data = new unsigned char [pout_len];
	memcpy(user_encrypted_data, pout_data, pout_len);
	int c = 0;
        while(pout_data[c] != NULL) {
                s.append(1, pout_data[c]);
                ++c;
        }
	return s;
}



std::string retrieveBid(std::string bid_name, shim_ctx_ptr_t ctx)
{
    	LOG_DEBUG(" +++ retrieveBid +++");
	uint32_t bid_bytes_len = -1;
	char _unencrypted_bid[128];
	const char* unencrypted_bid;

	get_state(bid_name.c_str(), (uint8_t*)_unencrypted_bid, sizeof(_unencrypted_bid) - 1, &bid_bytes_len, ctx);

	_unencrypted_bid[bid_bytes_len + 1] = '\0';
	unencrypted_bid = _unencrypted_bid;
	std::string result(unencrypted_bid);
	int length = result.length();
	result = result.substr(0, length-1);
	return result;
}


std::string retrieveAuctionResult(shim_ctx_ptr_t ctx)
{
    std::string result;
    LOG_DEBUG(" +++ retrieveBid +++");

    uint32_t bid_bytes_len = -1;
    int values[5];
    int max = 0;
    int secondmax = 0;
    std::string username;
    std::string username_second = "";
    //Retrieve all the bids
    for (int i = 0; i < user_count; i++) {
	char _value[128];
	uint32_t bid_bytes_len = -1;	
    	get_state(usernames[i].c_str(), (uint8_t*)_value, sizeof(_value) - 1, &bid_bytes_len, ctx);
	const char* value;
	_value[bid_bytes_len + 1] = '\0';
	value = _value;
	std::string result(value);
	int length = result.length();
	result = result.substr(0, length-1);
	int bid = stoi(result);
	if (bid>max) {
		secondmax = max;
		username_second = username;
		max = bid;
		username = usernames[i];
	}
    }

    //Encrypt the max value
    //int encrypted_value = encrypter(max, username, ctx);

    //int signed_value = sign(encrypted_value);

    return username_second;
}

// implements chaincode logic for invoke
int invoke(
    uint8_t* response,
    uint32_t max_response_len,
    uint32_t* actual_response_len,
    shim_ctx_ptr_t ctx)
{
    //LOG_DEBUG("Harsh: +++ Executing chaincode invocation +++");

    std::string function_name;
    std::vector<std::string> params;
    get_func_and_params(function_name, params, ctx);
    std::string result;

    if (function_name == "putTestVariable")
    {
	    std::string user_name = params[0];
	    result = putTestVariable(user_name, ctx);
    } 
    else if (function_name == "getTestVariable")
    {
            result = getTestVariable(ctx);
    }
    else if (function_name == "createUserPublicPrivateKey")
    {
	    std::string user_name = params[0];
	    result = createUserPublicPrivateKey(user_name, ctx);
    }
    else if (function_name == "createChaincodePublicPrivateKey")
    {
		result = createChaincodePublicPrivateKey(ctx);
    }
    else if (function_name == "retrieveChaincodePublicKey")
    {
	result = retrieveChaincodePublicKey(ctx);
    }
    else if (function_name == "encryptionSimulation")
    {
	result = encryptionSimulation(ctx);    
    }
    else if (function_name == "decryptAndStoreBid")
    {
	std::string value = params[1]; 
        std::string user_name = params[0];
        result = decryptAndStoreBid(user_name, value, ctx);
    }
    else if (function_name == "encrypter")
    {
	std::string data = params[0];
	result = encrypter( data, ctx);
    }
    else if (function_name == "retrieveBid")
    {
	std::string user_name = params[0];
	result = retrieveBid(user_name, ctx);
    }
    else if (function_name == "retrieveAuctionResult")
    {
        result = retrieveAuctionResult(ctx);
    }
    else if (function_name == "signingSimulation")
    {
	result = signingSimulation(ctx);
    }
    else
    {
        // unknown function
        LOG_DEBUG("Harsh: RECEIVED UNKNOWN transaction '%s'", function_name);
        return -1;
    }

    // check that result fits into response
    int neededSize = result.size();
    if (max_response_len < neededSize)
    {
        // error:  buffer too small for the response to be sent
        *actual_response_len = 0;
        return -1;
    }

    // copy result to response
    memcpy(response, result.c_str(), neededSize);
    *actual_response_len = neededSize;
    LOG_DEBUG("Harsh: Response: %s", result.c_str());
    LOG_DEBUG("+++ Executing done +++");
    return 0;
}
