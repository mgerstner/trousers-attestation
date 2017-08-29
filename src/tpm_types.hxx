#ifndef TPM_TYPES_HXX
#define TPM_TYPES_HXX

/*
 *
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 *
 */

// C++-lib
#include <vector>
#include <ostream>

// tpm-util
#include "tpm_trousers.hxx"

/**
 * \brief
 * 	Represents a key blob which can be returned from some TpmSession calls
 * \details
 * 	Memory handling is currently explicit, so you have to turn it to
 * 	freeKeyBlob() for correctness. This could be improved at a later stage
 * 	using destructors and/or reference counting
 **/
struct KeyBlob
{
	/*
	 * geniously the memory management isn't uniformly handled:
	 *
	 * some functions return internally allocated buffers that need to be
	 * freed by Tspi_Context_FreeMemory, some require an externally
	 * allocate buffer.
	 */
	bool lib_allocated = false;
	UINT32 length = 0;
	BYTE *data = nullptr;

	void reset()
	{
		lib_allocated = false;
		length = 0;
		data = nullptr;
	}
};

/**
 * \brief
 * 	Represents a PCR composite object, a kind of bitset for selection of
 * 	PCR registers
 **/
struct PcrComposite
{
	TSS_HPCRS handle;

	void selectIndex(const size_t index);
};

typedef std::vector<uint8_t> ByteVector;

/*
 * this is the required size of a nonce, cannot be larger / smaller
 *
 * According to TPM main spec part 2, 5.5 TPM_NONCE data structure
 */
const size_t NONCE_SIZE = 20;

/**
 * \brief
 * 	Output data for a TpmSession::quote operation
 **/
struct QuoteResult
{
	//! binary blob for the TPM_QUOTE_INFO[2] structure
	ByteVector pcr_data;
	//! 2048 bit RSA signature for pcr_data
	ByteVector signature_data;
};

/**
 * \brief
 * 	Binary representation of RSA key modulus and exponent
 **/
struct RsaKey
{
	ByteVector modulus;
	ByteVector exponent;
};

void printHex(std::ostream &o, const uint8_t* data, const size_t len);

inline void printHex(std::ostream &o, const ByteVector &v)
{
	return printHex(o, v.data(), v.size());
}

inline std::ostream& operator<<(std::ostream &o, const ByteVector &v)
{
	printHex(o, v);
	return o;
}

#endif // inc. guard

