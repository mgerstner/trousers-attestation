/*
 *
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 *
 */

// C++-lib
#include <iostream>
#include <fstream>
#include <sstream>

// OpenSSL
#include <openssl/rsa.h>
#include <openssl/pem.h>

// tpm-util
#include "tpm_exceptions.hxx"
#include "tpm_helper.hxx"
#include "tpm_util.hxx"

void TpmUtil::writeKeyBlob(const KeyBlob &blob, const std::string &label)
{
	if( ! blob.data )
	{
		throw UsageError("tried to write empty key blob");
	}

	std::ofstream file;
	std::stringstream ss;
	ss << "keyblob." << m_key_id.getValue() << "." << label;
	checkNotExisting(ss.str());
	file.open(ss.str());

	if( file )
	{
		file.write((char*)blob.data, blob.length);
		if( m_trace_calls.isSet() )
		{
			std::cout << "Written " << blob.length << " bytes to " << ss.str() << std::endl;
		}
	}

	if( ! file )
	{
		throw SysError("open/write to output file");
	}

	file.close();

	std::cout << "written blob file \"" << ss.str() << "\"\n";
}

void TpmUtil::checkNotExisting(const std::string &path)
{
	// this is a stupid non-atomic test for existance, but that's
	// C++ file capabilities for you ...
	std::ifstream test_file;
	test_file.open(path);
	if( test_file )
	{
		throw UsageError(
			std::string("file ") + path + " already exists"
		);
	}
}

struct RSAGuard
{
	RSAGuard(RSA *key) : m_key(key) {}

	~RSAGuard() { RSA_free(m_key); }

	RSA *m_key;
};

void TpmUtil::writeOpenSSLKey(const RsaKey &key, const std::string &label)
{
	RSA *sslkey = RSA_new();
	RSAGuard guard(sslkey);

	sslkey->n = BN_bin2bn(
		key.modulus.data(), key.modulus.size(), nullptr
	);
	sslkey->e = BN_bin2bn(
		key.exponent.data(), key.exponent.size(), nullptr
	);

	if( ! sslkey->n || ! sslkey->e )
	{
		throw SysError("converting modulus/exponent to BIGNUM");
	}

	std::stringstream ss;
	ss << "opensslkey." << m_key_id.getValue() << "." << label << ".pem";

	auto file = fopen(ss.str().c_str(), "wx");

	if( file == NULL )
	{
		throw SysError("open/write to output file");
	}

	if( PEM_write_RSA_PUBKEY(file, sslkey) != 1 )
	{
		throw SysError("write openSSL RSA key to file");
	}

	std::cout << "written openssl pem file \"" << ss.str() << "\"\n";
}

void TpmUtil::writeQuoteResult(const QuoteResult &res)
{
	std::cout << "PCR composite hash ("
		<< res.pcr_data.size() << " bytes):\n\n"
		<< res.pcr_data
		<< "\n\n";

	std::cout << "Signature data: ("
		<< res.signature_data.size() << " bytes):\n\n"
		<< res.signature_data
		<< "\n";

	const std::string hash_filename("quote_hash.txt");
	const std::string sig_filename("quote_signature.txt");
	checkNotExisting(hash_filename);
	std::ofstream out;
	out.open(hash_filename);
	if( ! out )
	{
		throw SysError("Failed to write hash to file");
	}
	out << res.pcr_data << std::flush;
	std::cout << "Wrote composite hash to " << hash_filename << "\n";
	out.close();

	checkNotExisting(sig_filename);
	out.open(sig_filename);
	if( ! out )
	{
		throw SysError("write signature to file");
	}
	out << res.signature_data << std::flush;
	std::cout << "Wrote signature data to " << sig_filename << "\n";
}

TSS_FLAG TpmUtil::getKeyType()
{
	if( ! m_key_type.isSet() )
	{
		throw UsageError("--key-type is required");
	}

	const auto &key_type = m_key_type.getValue();

	if( key_type == "signing" )
		return TSS_KEY_TYPE_SIGNING;
	else if( key_type == "identity" )
		return TSS_KEY_TYPE_IDENTITY;
	else if( key_type == "storage" )
		return TSS_KEY_TYPE_STORAGE;
	else if( key_type == "bind" )
		return TSS_KEY_TYPE_BIND;

	throw UsageError("Invalid --key-type encountered");
}

size_t TpmUtil::parseInt(const std::string &s)
{
	size_t parsed = 0;
	size_t ret = 0;

	try
	{
		 ret = std::stoul(s, &parsed);
	}
	catch( const std::exception &ex )
	{
		throw UsageError(std::string("Bad index ") + s);
	}

	if( parsed != s.size() )
	{
		throw UsageError(std::string("Extra characters in index ") + s);
	}

	return ret;
}

void TpmUtil::getPcrSelection(PcrComposite &composite)
{
	if( !m_pcr_selection.isSet() )
	{
		throw UsageError("--pcrs is required for this operation");
	}

	const auto selection = m_pcr_selection.getValue();
	auto parts = split(selection, ',');
	size_t start, end;

	for( auto &part: parts )
	{
		strip(part);

		auto range = split(part, '-');
		if( range.size() == 1 )
		{
			// no range at all
			start = parseInt(part);
			composite.selectIndex(start);
		}
		else if( range.size() == 2 )
		{
			start = parseInt(range[0]);
			end = parseInt(range[1]);

			if( start > end )
			{
				throw UsageError(std::string("Bad range ") + part);
			}

			for( size_t i = start; i <= end; i++ )
			{
				composite.selectIndex(i);
			}
		}
		else
		{
			throw UsageError(
				std::string("Unsupported --pcrs element: ") + part
			);
		}
	}
}

KeyBlob TpmUtil::readBlob(const std::string &path)
{
	std::ifstream f;
	f.open(path);

	if( ! f )
	{
		throw SysError(std::string("open file \"") + path + "\"");
	}

	KeyBlob blob;
	m_session.allocKeyBlob(blob);

	try
	{
		size_t read = 0;

		while( read < blob.length )
		{
			f.read((char*)(blob.data + read), blob.length - read);

			read += f.gcount();

			if( f.eof() )
				break;
			else if( f.fail() )
			{
				throw SysError("read from file");
			}
		}

		blob.length = read;

		if( ! f.eof() )
		{
			std::stringstream ss;
			ss << "File " << path
				<< " bigger than supported (max "
				<< blob.length << " bytes)";
			throw UsageError(ss.str());
		}
	}
	catch( const std::exception &ex )
	{
		m_session.freeKeyBlob(blob);
		throw;
	}

	return blob;
}

void TpmUtil::run()
{
	m_session.init();
	std::cout << "TPM session initialized" << std::endl;

	if( m_create_key.isSet() )
	{
		assertKeyID();
		m_session.authorizeOwner();
		const auto our_uuid = m_session.getUUID(m_key_id.getValue());
		m_session.createKey(getKeyType(), our_uuid);
		std::cout << "Key of type " << m_key_type.getValue()
			<< " with ID " << m_key_id.getValue()
			<< " created" << std::endl;
	}
	else if( m_fetch_key.isSet() )
	{
		auto key_handle = loadKey();
		KeyBlob blob, blob_der;
		m_session.getKeyBlob(key_handle, TSS_TSPATTRIB_KEYBLOB_BLOB, blob);
		writeKeyBlob(blob, "private");

		m_session.getKeyBlob(key_handle, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, blob);
		writeKeyBlob(blob, "public");
		m_session.getDERBlob(TSS_BLOB_TYPE_PUBKEY, blob, blob_der);
		writeKeyBlob(blob_der, "public.der");

		/*
		 * this is the only way I found until now to extract RSA 2048
		 * bit public key information in a portable way. using the
		 * plain modulus and exponent we can use openssl to write a
		 * usable PEM file.
		 */
		RsaKey rsa_key;
		m_session.getKeyInfo(key_handle, rsa_key);
		writeOpenSSLKey(rsa_key, "public");

		m_session.freeKeyBlob(blob);
		m_session.freeKeyBlob(blob_der);
	}
	else if( m_get_quote.isSet() )
	{
		auto key_handle = loadKey();
		PcrComposite pcrs;
		m_session.createPcrComposite(pcrs);
		getPcrSelection(pcrs);

		const std::string pseudo_nonce_src = \
			"TPM is not a very robust concept";
		ByteVector pseudo_nonce;
		pseudo_nonce.assign(pseudo_nonce_src.begin(), pseudo_nonce_src.end());
		pseudo_nonce.resize(NONCE_SIZE);
		std::cout << "Using nonce data: " << pseudo_nonce << std::endl;

		auto result = m_session.quote(key_handle, pcrs, pseudo_nonce);
		std::cout << "Completed quote operation:\n\n";

		writeQuoteResult(result);
	}
	else if( m_register_key.isSet() )
	{
		assertKeyID();
		auto blob = readBlob(m_register_key.getValue());
		const auto key_uuid = m_session.getUUID(m_key_id.getValue());
		m_session.registerKey(blob, key_uuid);
		std::cout << "Registered key blob "
			<< m_register_key.getValue()
			<< " as key ID " << m_key_id.getValue() << std::endl;
	}
	else if( m_export_uuid.isSet() )
	{
		assertKeyID();
		const auto key_uuid = m_session.getUUID(m_key_id.getValue());
		m_session.exportUUID(key_uuid, m_export_uuid.getValue());
		std::cout << "Wrote UUID file to " << m_export_uuid.getValue() << "\n";
	}
	else
	{
		std::cerr << "No action selected, nothing to do\n";
	}
}

int main(const int argc, const char **argv)
{
	try
	{
		TpmUtil util;
		util.parseArgs(argc, argv);
		util.run();
		return 0;
	}
	catch( const std::exception &ex )
	{
		std::cerr << "Failed: " << ex.what() << std::endl;
		return 1;
	}
}

