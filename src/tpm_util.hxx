/*
 *
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 *
 */

#ifndef TPM_UTIL_HXX
#define TPM_UTIL_HXX

// tpm-util
#include "tpm_session.hxx"

// third-party
#include <tclap/CmdLine.h>

/**
 * \brief
 * 	TpmUtil application that utilizes TpmSession for easy command line
 * 	access to TPM features
 **/
class TpmUtil
{
public:
	TpmUtil() :
		m_cmdline(
			"A utility for working with trousers 1.2 TPMs.\n"
			"Optional environment variables:\n"
			"TPM_PASS: passphrase for the TPM\n"
			"SRK_PASS: passphrase for the SRK"
		),
		m_create_key("c", "create-key", "Create a new key according to parameters", m_cmdline, false),
		m_fetch_key("f", "fetch-key", "Fetches public key and private key blob for the given --key-uuid in TPM portable data format", m_cmdline, false),
		m_get_quote("q", "get-quote", "Performs a quote using the given --key-id and --pcrs", m_cmdline, false),
		m_register_key("r", "register-key", "Registers the given wrapped key blob file in the TPM. Requires -u.",
			false,
			"",
			"path to keyblob file (non-DER encoded)",
			m_cmdline
		),
		m_export_uuid("", "export-uuid", "Exports the uuid given with -u into a binary file understood by tpm-quote-tools",
			false, "", "path where to create the binary uuid file",
			m_cmdline
		),
		m_trace_calls("", "trace", "Traces trousers library calls and results", m_cmdline, false),
		m_key_id(
			"u", "key-id",
			"The key ID to work with for creating/fetching keys.",
			false,
			0,
			"Unsigned integer in [0,255]",
			m_cmdline
		),
		m_key_type(
			"t", "key-type",
			"The key type to use for creating keys.",
			false,
			"",
			"One of 'signing', 'identity', 'storage', 'bind'",
			m_cmdline
		),
		m_pcr_selection(
			"p", "pcrs",
			"The numbers of pcrs to use in operations.",
			false,
			"",
			"Colon separated list of indices, also ranges are possible like 1,3,5-8",
			m_cmdline
		)
	{

	}

	void parseArgs(const int argc, const char **argv)
	{
		m_cmdline.parse(argc, argv);

		m_session.setDebug( m_trace_calls.isSet() );
	}

	void run();

protected:

	void writeKeyBlob(const KeyBlob &blob, const std::string &label);

	void writeOpenSSLKey(const RsaKey &key, const std::string &label);

	void writeQuoteResult(const QuoteResult &res);

	void checkNotExisting(const std::string &path);

	TSS_FLAG getKeyType();

	void assertKeyID()
	{
		if( !m_key_id.isSet() )
		{
			throw UsageError("--key-id is required for this operation");
		}

		const auto val = m_key_id.getValue();

		if( val > UINT8_MAX )
		{
			throw UsageError("--key-id is out of range");
		}
	}

	TSS_HKEY loadKey()
	{
		assertKeyID();
		const auto key_uuid = m_session.getUUID(m_key_id.getValue());

		// if we don't authorize the SRK then we can't load the key.
		// it's unclear how to know in advance which is the parent key
		// we need to authorize against, probably via key property
		// query.
		// for now we assume it's always the SRK
		m_session.authorizeSRK();

		return m_session.loadKey(key_uuid);
	}

	void getPcrSelection(PcrComposite &composite);

	size_t parseInt(const std::string &s);

	KeyBlob readBlob(const std::string &path);

protected:
	TCLAP::CmdLine m_cmdline;
	TCLAP::SwitchArg m_create_key;
	TCLAP::SwitchArg m_fetch_key;
	TCLAP::SwitchArg m_get_quote;
	TCLAP::ValueArg<std::string> m_register_key;
	TCLAP::ValueArg<std::string> m_export_uuid;
	TCLAP::SwitchArg m_trace_calls;
	TCLAP::ValueArg<size_t> m_key_id;
	TCLAP::ValueArg<std::string> m_key_type;
	TCLAP::ValueArg<std::string> m_pcr_selection;
	TpmSession m_session;
};

#endif // inc. guard

