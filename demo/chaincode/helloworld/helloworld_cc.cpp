#include "shim.h"
#include "logging.h"
#include <string>
#include <ctime>
#include <stdio.h>
#include <cstdlib>
#include <math.h>

#define OK "OK"
#define NOT_FOUND "Bid not found"

#define MAX_VALUE_SIZE 1024
double encryption_key;
double n;

int gcd(int a, int h)
{   
    int temp;
    while (1)
    {   
        temp = a%h; 
        if (temp == 0)
          return h;
        a = h; 
        h = temp;
    }
}

//  Add bid_name, value to ledger
std::string storeBid(std::string bid_name, int value, shim_ctx_ptr_t ctx)
{
    LOG_DEBUG("HelloworldCC: +++ storeBid:  +++");
    
    double p=7;
    double q=3;
    // First part of public key:
    n = p*q;

    // Finding other part of public key.
    // e stands for encrypt
    encryption_key = 2;
    double phi = (p-1)*(q-1);
    while (encryption_key < phi)
    {
        // e must be co-prime to phi and
        // smaller than phi.
        if (gcd(encryption_key, phi)==1)
            break;
        else
            encryption_key++;
    }

    // Private key (d stands for decrypt)
    // choosing d such that it satisfies
    // d*e = 1 + k * totient
    int k = 2;  // A constant value
    double decryption_key = (1 + (k*phi))/encryption_key;

    // Encryption c = (msg ^ e) % n
    double encrypted_object = pow(value, encryption_key);
    encrypted_object = fmod(encrypted_object, n);

    put_state(bid_name.c_str(), (uint8_t*)&encrypted_object, sizeof(int), ctx);

    return std::to_string(decryption_key);
}

std::string retrieveBid(std::string bid_name, double decryption_key, shim_ctx_ptr_t ctx)
{
    std::string result;
    LOG_DEBUG("HelloworldCC: +++ retrieveBid +++");

    uint32_t bid_bytes_len = 0;
    uint8_t bid_bytes[MAX_VALUE_SIZE];
    get_state(bid_name.c_str(), bid_bytes, sizeof(bid_bytes), &bid_bytes_len, ctx);

    //  check if bid_name exists
    if (bid_bytes_len > 0)
    {
	double encrypted_object = std::stod(std::to_string((int)(*bid_bytes)));
	double decrypted_value = pow(encrypted_object, decryption_key);
	decrypted_value =fmod(decrypted_value, n);
        result = bid_name +   ":" +  std::to_string(decrypted_value);
     } else {
        //  bid does not exist
        result = NOT_FOUND;
    }
    return result;
}

// implements chaincode logic for invoke
int invoke(
    uint8_t* response,
    uint32_t max_response_len,
    uint32_t* actual_response_len,
    shim_ctx_ptr_t ctx)
{
    LOG_DEBUG("HelloworldCC: +++ Executing helloworld chaincode invocation +++");

    std::string function_name;
    std::vector<std::string> params;
    get_func_and_params(function_name, params, ctx);
    std::string bid_name = params[0];
    std::string result;

    if (function_name == "storeBid")
    {
        int value = std::stoi (params[1]);
        result = storeBid(bid_name, value, ctx);
    }
    else if (function_name == "retrieveBid")
    {
        double decryption_key = std::stod (params[1]);
        result = retrieveBid(bid_name, decryption_key, ctx);
    }
    else
    {
        // unknown function
        LOG_DEBUG("HelloworldCC: RECEIVED UNKNOWN transaction '%s'", function_name);
        return -1;
    }

    // check that result fits into response
    int neededSize = result.size();
    if (max_response_len < neededSize)
    {
        // error:  buffer too small for the response to be sent
        LOG_DEBUG("HelloworldCC: Response buffer too small");
        *actual_response_len = 0;
        return -1;
    }

    // copy result to response
    memcpy(response, result.c_str(), neededSize);
    *actual_response_len = neededSize;
    LOG_DEBUG("HelloworldCC: Response: %s", result.c_str());
    LOG_DEBUG("HelloworldCC: +++ Executing done +++");
    return 0;
}
