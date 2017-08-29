/*
 *
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 *
 */

// C++-lib
#include <iostream>
#include <cstring>
#include <fstream>
#include <unistd.h>

// tpm-util
#include "tpm_session.hxx"
#include "tpm_exceptions.hxx"

TpmSession::~TpmSession()
{
	if( ! m_initialized )
		return;
	Tspi_Context_FreeMemory(m_context, NULL);
	Tspi_Context_Close(m_context);
}

void TpmSession::checkCall(const char *action)
{
	if( m_debug )
	{
		std::cerr << action << " -> " << m_res << "\n";
	}

	if( m_res == TSS_SUCCESS )
		return;

	throw TpmException(m_res, action);
}

void TpmSession::init()
{
	if( m_initialized )
	{
		return;
	}

	m_res = Tspi_Context_Create(&m_context);
	checkCall("Context_Create");
	m_res = Tspi_Context_Connect(m_context, NULL);
	checkCall("Context_Connect");
	m_res = Tspi_Context_GetTpmObject(m_context, &m_tpm_handle);
	checkCall("GetTpmObject");

	m_initialized = true;
}

void TpmSession::freeKeyBlob(KeyBlob &blob)
{
	if(!blob.data)
	{
		return;
	}

	if(blob.lib_allocated)
	{
		freeContextMem(blob.data);
	}
	else
	{
		delete[] blob.data;
	}

	blob.reset();
}

void TpmSession::freeContextMem(BYTE *mem)
{
	Tspi_Context_FreeMemory( m_context, mem );
}

void TpmSession::allocKeyBlob(KeyBlob &blob)
{
	freeKeyBlob(blob);

	blob.length = 4096;
	blob.data = new BYTE[blob.length];
}

TSS_HKEY TpmSession::loadKey(TSS_UUID uuid, const bool user_else_system)
{
	TSS_HKEY ret;

	m_res = Tspi_Context_LoadKeyByUUID(
		m_context,
		user_else_system ? TSS_PS_TYPE_USER : TSS_PS_TYPE_SYSTEM,
		uuid,
		&ret
	);

	checkCall("LoadKeyByUUID");

	return ret;
}

void TpmSession::registerKey(const KeyBlob &blob, TSS_UUID id)
{
	auto srk = authorizeSRK();
	TSS_HKEY blob_handle;
	m_res = Tspi_Context_LoadKeyByBlob(
		m_context, srk, blob.length, blob.data, &blob_handle
	);

	checkCall("LoadKeyByBlob");

	m_res = Tspi_Context_RegisterKey(
		m_context, blob_handle, TSS_PS_TYPE_SYSTEM,
		id, TSS_PS_TYPE_SYSTEM, TSS_UUID_SRK
	);

	checkCall("RegisterKey");
}

void TpmSession::getKeyBlob(TSS_HKEY key, TSS_FLAG type, KeyBlob &blob)
{
	freeKeyBlob(blob);

	m_res = Tspi_GetAttribData(
		key,
		TSS_TSPATTRIB_KEY_BLOB,
		type,
		&blob.length,
		&blob.data
	);

	checkCall("GetAttribData (getKeyBlob)");

	blob.lib_allocated = true;
}

/*
 * this DER blob thing is actually nothing openssl or other standard software
 * can work with. the openssl tpm engine can do but with very little
 * documentation about the use cases.
 *
 * the definition of the data structure is found in TSS spec and TPM 1.2 spec.
 * Basically is a custom ASN data structure, containing an enum for the
 * algorithm, then the public key RSA parameters, exponent and modulus. Not
 * very accessible to us.
 *
 * also see 3.23 "portable data"
 */
void TpmSession::getDERBlob(TSS_FLAG type, const KeyBlob &in, KeyBlob &out)
{
	if( &in == &out )
	{
		throw UsageError("Same KeyBlob used for in/out in getDERBlob()");
	}

	allocKeyBlob(out);

	m_res = Tspi_EncodeDER_TssBlob(
		in.length, in.data, type, &out.length, out.data
	);

	checkCall("EncodeDER (getDERKeyBlob)");
}

void TpmSession::getKeyInfo(TSS_HKEY key, RsaKey &info)
{
	KeyBlob blob;

	m_res = Tspi_GetAttribData(
		key,
		TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT,
		&blob.length,
		&blob.data
	);

	checkCall("GetAttribData exponent (getKeyInfo)");

	info.exponent.assign( blob.data, blob.data + blob.length );

	m_res = Tspi_GetAttribData(
		key,
		TSS_TSPATTRIB_RSAKEY_INFO,
		TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
		&blob.length,
		&blob.data
	);

	checkCall("GetAttribData modulus (getKeyInfo)");

	info.modulus.assign( blob.data, blob.data + blob.length );
}

TSS_HOBJECT TpmSession::createKey(TSS_FLAG type, TSS_UUID id, TSS_UUID parent_uuid)
{
	TSS_HOBJECT key_object;

	m_res = Tspi_Context_CreateObject(
		m_context,
		TSS_OBJECT_TYPE_RSAKEY,
		type | TSS_KEY_SIZE_2048,
		&key_object
	);

	checkCall("CreateObject (key)");

	auto parent_key = loadKey(parent_uuid);

	authorizeKey(parent_key);

	m_res = Tspi_Key_CreateKey(
		key_object,
		parent_key,
		0
	);

	checkCall("CreateKey");

	Tspi_Context_RegisterKey(
		m_context,
		key_object,
		TSS_PS_TYPE_SYSTEM,
		id,
		TSS_PS_TYPE_SYSTEM,
		parent_uuid
	);

	checkCall("RegisterKey");

	return key_object;
}

TSS_UUID TpmSession::getUUID(const uint8_t id) const
{
	/*
	 * turns out this is a big struct but only the last two bits seem to
	 * matter:
	 *
	 * {0,0,0,0,0,{0,0,0,0,x,y}}
	 *
	 * x == 0 -> keys from the spec
	 * x == 1 -> owner evict keys
	 * all others are custom keys
	 */

	return {0,0,0,0,0,{0,0,0,0,7,id}};
}

void TpmSession::exportUUID(TSS_UUID uuid, const std::string &out_path)
{
	std::ofstream out;
	out.open(out_path, out.trunc);

	if( ! out )
	{
		throw SysError(std::string("Failed to open output file \"") + out_path + "\"");
	}

	/* in tpm_mkuuid.c the struct is simply written out as an opaque
	 * object */

	out.write((char*)&uuid, sizeof(uuid));

	if( !out.good() )
	{
		throw SysError("Failed to write UUID object to file");
	}
}

QuoteResult TpmSession::quote(
	TSS_HKEY sign_key,
	const PcrComposite &composite,
	const ByteVector &nonce
)
{
	TSS_VALIDATION validation;
	//std::memset(&validation, 0, sizeof(validation));

	validation.ulExternalDataLength = nonce.size();
	validation.rgbExternalData = (BYTE*)nonce.data();

	/*
	 * for an unexplainable reason the Quote2 operation fails with
	 *
	 * "Invalid data size" (43)
	 *
	 * the only difference to Quote(1) are the unused version_info
	 * parameters. tpm_getquote(8) uses the same calling approach,
	 * however. Couldn't test tpm_getquote(8), because it doesn't support
	 * passwords for SRK/TPM.
	 */
#if 0
	UINT32 version_info_len = 0;
	BYTE *version_info = nullptr;

	m_res = Tspi_TPM_Quote2(
		m_tpm_handle,
		sign_key,
		FALSE, /* add TPM version to output */
		composite.handle, /* pcrs composite */
		&validation,
		&version_info_len, /* version info size */
		&version_info /* version info ptr */
	);
#else
	m_res = Tspi_TPM_Quote(
		m_tpm_handle,
		sign_key,
		composite.handle, /* pcrs composite */
		&validation
	);
#endif

	checkCall("quote");

	QuoteResult res;

	res.pcr_data.resize(validation.ulDataLength);
	std::memcpy(
		res.pcr_data.data(),
		validation.rgbData,
		res.pcr_data.size()
	);

	res.signature_data.resize(validation.ulValidationDataLength);
	std::memcpy(
		res.signature_data.data(),
		validation.rgbValidationData,
		res.signature_data.size()
	);

	freeContextMem(validation.rgbData);
	freeContextMem(validation.rgbValidationData);

	return res;
}

std::string TpmSession::getPass() const
{
	// XXX bad idea to use getpass(), but tpm-tools do it too ;-)
	const std::string label = m_cur_auth_topic + ": ";
	auto pass = getpass(label.c_str());

	if( !pass )
	{
		throw SysError("getpass()");
	}

	return pass;
}

void TpmSession::createPcrComposite(PcrComposite &composite)
{
	m_res = Tspi_Context_CreateObject(
		m_context,
		TSS_OBJECT_TYPE_PCRS,
		TSS_PCRS_STRUCT_INFO,
		&(composite.handle)
	);

	checkCall("createPcrComposite");
}

void TpmSession::authorizeOwner()
{
	m_cur_auth_topic = "Owner authorization";
	return authorizeObject(m_tpm_handle, "TPM");
}

TSS_HKEY TpmSession::authorizeSRK()
{
	m_cur_auth_topic = "SRK authorization";
	auto srk_handle = loadKey(TSS_UUID_SRK);
	authorizeObject(srk_handle, "SRK");
	return srk_handle;
}

void TpmSession::authorizeKey(TSS_HKEY key)
{
	m_cur_auth_topic = "Key authorization";
	return authorizeObject(key, "SRK");
}

void TpmSession::authorizeObject(TSS_HOBJECT obj, const std::string &type)
{
	TSS_HPOLICY policy;

	m_res = Tspi_GetPolicyObject(obj, TSS_POLICY_USAGE, &policy);

	checkCall("GetPolicyObject (owner auth)");

	/*
	 * allow the passphrase to be given via the environment
	 */
	const std::string envvar = type + "_PASS";
	auto envvalue = ::getenv(envvar.c_str());

	auto pass = envvalue ? std::string(envvalue) : getPass();

	m_res = Tspi_Policy_SetSecret(
		policy,
		TSS_SECRET_MODE_PLAIN,
		pass.size(),
		(BYTE*)&(pass[0])
	);

	checkCall("Policy_SetSecret (owner auth)");
}

