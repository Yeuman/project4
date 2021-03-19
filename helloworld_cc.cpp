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
#define RSA_MOD_SIZE 128 //hardcode n size to be 384
#define RSA_E_SIZE 4 //hardcode e size to be 4

#define MAX_VALUE_SIZE 1024
int public_key = 9;
int private_key = 5;
int user_count = 0;
std::map<int, std::string> usernames;


std::string storePublicKey(std::string user_name, int value, shim_ctx_ptr_t ctx)
{
	put_state(user_name.c_str(), (uint8_t*)&value, sizeof(value), ctx);
}

std::string  retrieveChaincodePublicKey(shim_ctx_ptr_t ctx)
{
	uint32_t little_endian_e = 999;
    	uint8_t *le_n = NULL;
    	void *key = NULL;
	void *public_key = NULL;
	void *private_key = NULL;
    	size_t temp_encrypted_size = 0;

        //create public exponent value represented in little endian
        //

        le_n = (uint8_t *)malloc(RSA_MOD_SIZE);
        for (size_t i = 0; i<RSA_MOD_SIZE; i++) {
            le_n[i] = 65;//create little endian n
        }

	//if (sgx_create_rsa_pub1_key(RSA_MOD_SIZE, RSA_E_SIZE, (const unsigned char *)le_n,
        //    (const unsigned char *)(&little_endian_e), &key) != SGX_SUCCESS) {
        //}
	
	unsigned char p_n, p_d, p_e, p_p, p_q, p_dmp1, p_dmq1, p_iqmp; 
	p_e = 65537;

	std::string s = "Test";

	if (sgx_create_rsa_key_pair(RSA_MOD_SIZE, RSA_E_SIZE, &p_n, &p_d, &p_e, &p_p, &p_q, &p_dmp1, &p_dmq1, &p_iqmp) == SGX_SUCCESS){ 
		s = s + "Created key pair";
	}

	if(sgx_create_rsa_pub1_key(RSA_MOD_SIZE, RSA_E_SIZE, &p_n, &p_e, &public_key) == SGX_SUCCESS) {
		s = s + "Reached Public Key phase";
	}

	if(sgx_create_rsa_priv2_key(RSA_MOD_SIZE, RSA_E_SIZE, &p_e, &p_p, &p_q, &p_dmp1, &p_dmq1, &p_iqmp, &private_key) == SGX_SUCCESS) {
		s = s + "Reached Private Key phase";
	}	

	unsigned char pout_data = NULL;
	uint8_t *encrypted_ppid, *decrypted_ppid;
	size_t pout_len = 0;

	const unsigned char pin_data = 65537;
	const size_t pin_len = sizeof(&pin_data);

	if(sgx_rsa_pub_encrypt_sha256(public_key, NULL, &pout_len, &pin_data, pin_len) == SGX_SUCCESS) {
		s = s + "Encrypted";
	}

	if(sgx_rsa_pub_encrypt_sha256(public_key, encrypted_ppid, &pout_len, &pin_data, pin_len) == SGX_SUCCESS) {
                s = s + "Encrypted Part 2";
        }

	size_t decrypted_len = 0;

	if(sgx_rsa_priv_decrypt_sha256(private_key, NULL, &decrypted_len, encrypted_ppid, pout_len) == SGX_SUCCESS) {
		s = s + "Decrypted";
	}

	if(sgx_rsa_priv_decrypt_sha256(private_key, decrypted_ppid, &decrypted_len, encrypted_ppid, pout_len) == SGX_SUCCESS) {
                s = s + "Decrypted Part 2";
        }


	uint8_t dst[384];
	size_t dst_len = 384;
	unsigned char *src = new unsigned char();
	*src = 72; 
	size_t src_len = sizeof(src);
	//if(sgx_rsa_pub_encrypt_sha256(public_key, dst, &dst_len, src, src_len) != SGX_SUCCESS) {
	//}

	uint8_t unenc_src[384];
        size_t unenc_src_len = 384;

	//if(sgx_rsa_priv_decrypt_sha256(private_key, unenc_src, &unenc_src_len, dst, dst_len) != SGX_SUCCESS) {
	//}


	//std::string *sp = static_cast<std::string*>(key);

	if(unenc_src == src) {
		s = "Finally";
	}
	

	return s;
}

int unsign(int signed_value, std::string user_name, shim_ctx_ptr_t ctx)
{
	int user_public_key;
        uint32_t bid_bytes_len = -1;
	get_state(user_name.c_str(), (uint8_t*)&user_public_key, sizeof(user_public_key), &bid_bytes_len, ctx);
	
	int unsigned_value = signed_value/user_public_key;

	return unsigned_value;
}

int sign(int encrypted_value)
{
	return encrypted_value* private_key;
}

int decrypter(int encrypted_value)
{
	return encrypted_value/private_key;
}

int encrypter(int value, std::string user_name, shim_ctx_ptr_t ctx) {
        int user_public_key;
	uint32_t bid_bytes_len = -1;
	get_state(user_name.c_str(), (uint8_t*)&user_public_key, sizeof(user_public_key), &bid_bytes_len, ctx);
	return value*user_public_key;
}

//  Add bid_name, value to ledger
std::string storeBid(std::string user_name, int value, shim_ctx_ptr_t ctx)
{
    LOG_DEBUG("+++ storeBid:  +++");
    //First unsign the value. Confirm the user identity
    int encrypted_value;
    encrypted_value = unsign(value, user_name, ctx);

    //Decrypt the unsigned value
    int decrypted_value;
    decrypted_value = decrypter(encrypted_value);

    //Store on the ledger
    put_state(user_name.c_str(), (uint8_t*)&decrypted_value, sizeof(decrypted_value), ctx);

    usernames[user_count] = user_name;
    return "SUCCESS in storing the value";
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

    if (function_name == "storeBid")
    {
	std::string::size_type sz; 
        std::string user_name = params[0];
        int value = std::stoi (params[1], &sz);
        result = storeBid(user_name, value, ctx);
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
    else if (function_name == "storePublicKey")
    {
	int user_public_key = std::stoi(params[1]);
	std::string user_name = params[0];
	result = storePublicKey(user_name, user_public_key, ctx);
    }
    else if (function_name == "retrieveChaincodePublicKey")
    {
	result = retrieveChaincodePublicKey(ctx);
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
