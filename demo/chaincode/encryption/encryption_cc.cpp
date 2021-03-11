#include "shim.h"
#include<map>
#include "logging.h"
#include <string>
#include <ctime>
#include <stdio.h>
#include <cstdlib>
#include <math.h>
#include <random>
#include<openssl>

#define OK "OK"
#define NOT_FOUND "Bid not found"

#define MAX_VALUE_SIZE 1024
int public_key = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB-----END PUBLIC KEY-----";


int private_key = "-----BEGIN RSA PRIVATE KEY-----MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlFL0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5kX6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2eplU9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=-----END RSA PRIVATE KEY-----";
int user_count = 0;
std::map<int, std::string> usernames;

std::string storePublicKey(std::string user_name, int value, shim_ctx_ptr_t ctx)
{
	put_state(user_name.c_str(), (uint8_t*)&value, sizeof(value), ctx);
}

std::string  retrieveChaincodePublicKey(shim_ctx_ptr_t ctx)
{
	return std::to_string(public_key);
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
