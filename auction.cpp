#include "shim.h"
#include<map>
#include "logging.h"
#include <string>
#include <ctime>
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
	
	userPublicKeys[user_name] = public_key;
	
	return private_key;
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
}

// To be called to retrieve the chaincode public key
std::string  retrieveChaincodePublicKey(shim_ctx_ptr_t ctx)	
{
	return chaincode_public_key;
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
	size_t decrypted_len = 0;

	if(sgx_rsa_priv_decrypt_sha256(chaincode_private_key, NULL, &decrypted_len, pout_data, sizeof(pout_data)) == SGX_SUCCESS) {
		s = s + "Decrypted";
	}

	unsigned char decrypted_pout_data[decrypted_len];

	if(sgx_rsa_priv_decrypt_sha256(chaincode_private_key, decrypted_pout_data, &decrypted_len, pout_data, sizeof(pout_data)) == SGX_SUCCESS) {
                s = s + "Decrypted Part 2";
        }
	
	put_state(user_name.c_str(), (uint8_t*)&decrypted_pout_data, sizeof(decrypted_pout_data), ctx);
}

// Function to encrypt the bid for the user
std::string encrypter(std::string pin_data, shim_ctx_ptr_t ctx) {
	
	if(sgx_rsa_pub_encrypt_sha256(chaincode_public_key, NULL, &pout_len, (unsigned char *)pin_data, strlen(pin_data)) == SGX_SUCCESS) {
		
	}

	unsigned char pout_data[pout_len];
	
        if(sgx_rsa_pub_encrypt_sha256(chaincode_public_key, pout_data, &pout_len, (unsigned char *)pin_data, strlen(pin_data)) == SGX_SUCCESS) {
                
        }
	return pout_data
}



std::string retrieveBid(std::string bid_name, shim_ctx_ptr_t ctx)
{
	std::string result;
    	LOG_DEBUG(" +++ retrieveBid +++");
	uint32_t bid_bytes_len = -1;
	int unencrypted_object;

	get_state(bid_name.c_str(), (uint8_t*)&unencrypted_object, sizeof(unencrypted_object), &bid_bytes_len, ctx);

	result = std::to_string(unencrypted_object);
	return result;
}


std::string retrieveAuctionResult(shim_ctx_ptr_t ctx)
{
    std::string result;
    LOG_DEBUG(" +++ retrieveBid +++");

    uint32_t bid_bytes_len = -1;
    int values[5];
    int max = 0;
    std::string username;
    //Retrieve all the bids
    for (int i = 0; i < usernames.size(); i++) {
	int value;
	uint32_t bid_bytes_len = -1;	
    	get_state(usernames[i].c_str(), (uint8_t*)&value, sizeof(value), &bid_bytes_len, ctx);
	values[i] = value;
	if (value>max) {
		max = value;
		username = usernames[i];
	}
    }

    //Encrypt the max value
    int encrypted_value = encrypter(max, username, ctx);

    int signed_value = sign(encrypted_value);

    return std::to_string(signed_value);
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

    if (function_name == "createUserPublicPrivateKey")
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
