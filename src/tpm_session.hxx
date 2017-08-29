#ifndef TPM_SESSION_HXX
#define TPM_SESSION_HXX

/*
 *
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 *
 */

// tpm-util
#include "tpm_trousers.hxx"
#include "tpm_types.hxx"

/**
 * \brief
 * 	Basic wrapper around TrouSerS TPM 1.2 stack operations
 * \details
 * 	This object keeps state about the various tpm and context handles that
 * 	are required time and again. It wraps the operations on those
 * 	handles.
 **/
class TpmSession
{
public: // functions

	~TpmSession();

	void setDebug(const bool debug) { m_debug = debug; }

	void init();

	TSS_HOBJECT createKey(
		TSS_FLAG type, TSS_UUID id, TSS_UUID parent = TSS_UUID_SRK
	);

	TSS_UUID getUUID(const uint8_t id) const;

	/**
	 * \brief
	 * 	Exports the given UUID in a format understood by
	 * 	tpm-quote-tools
	 **/
	void exportUUID(TSS_UUID uuid, const std::string &out_path);

	/**
	 * \brief
	 * 	Load the given key uuid from the TPM and return a handle for it
	 **/
	TSS_HKEY loadKey(TSS_UUID uuid, const bool user_else_system = false);

	/**
	 * \brief
	 * 	Registers a key from the given external key blob data under
	 * 	the given UUID in the TPM
	 **/
	void registerKey(const KeyBlob &blob, TSS_UUID id);

	/**
	 * \brief
	 * 	Returns a binary key blob encoded in a TPM specific format
	 * 	acc. to spec
	 **/
	void getKeyBlob(TSS_HKEY key, TSS_FLAG type, KeyBlob &blob);

	/**
	 * \brief
	 * 	Returns the binary key blob wrapped in a DER structure
	 * 	specific to TSS/TPM spec
	 **/
	void getDERBlob(TSS_FLAG type, const KeyBlob &in, KeyBlob &out);

	/**
	 * \brief
	 * 	Returns the raw RSA key parameters for the given key
	 **/
	void getKeyInfo(TSS_HKEY key, RsaKey &info);

	/**
	 * \brief
	 * 	Perform a TPM quote operation using the given signing key and
	 * 	PCR set
	 * \details
	 * 	The quote operation will create a signature for the values of
	 * 	the selected PCRS using the given signing key. The nonce will
	 * 	be part of the signed data and it is very important for
	 * 	cryptographic security of remote attestation to avoid replay
	 * 	attacks.
	 *
	 * 	The nonce must be as random and unique as possible. If it
	 * 	repeats then a replay attack is possible for an attacker.
	 **/
	QuoteResult quote(
		TSS_HKEY sign_key,
		const PcrComposite &composite,
		const ByteVector &nonce
	);

	void authorizeOwner();
	/**
	 * \brief
	 * 	Authorizes the SRK and returns handle to it
	 **/
	TSS_HKEY authorizeSRK();
	void authorizeKey(TSS_HKEY key);

	void freeKeyBlob(KeyBlob &blob);

	//! allocates suitable heap memory in the given block, can later be
	//! freed via freeKeyBlob()
	void allocKeyBlob(KeyBlob &blob);

	void createPcrComposite(PcrComposite &composite);

protected:

	void checkCall(const char *action);

	std::string getPass() const;

	void authorizeObject(TSS_HOBJECT obj, const std::string &type);

	void freeContextMem(BYTE *mem);

protected:

	TSS_RESULT m_res = TSS_SUCCESS;
	TSS_HCONTEXT m_context;
	TSS_HTPM m_tpm_handle;
	bool m_debug = false;
	std::string m_cur_auth_topic;
	bool m_initialized = false;
};

#endif // inc. guard

