/*
 *
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 *
 */

// C++-lib
#include <iomanip>

// tpm-util
#include "tpm_types.hxx"
#include "tpm_exceptions.hxx"

void PcrComposite::selectIndex(const size_t index)
{
	auto res = Tspi_PcrComposite_SelectPcrIndex(handle, index);

	if( res != TSS_SUCCESS )
	{
		throw TpmException(res, "selectPcrIndex");
	}
}

void printHex(std::ostream &o, const uint8_t* data, const size_t len)
{
	const auto backup_flags = o.flags();
	o << std::setfill('0');

	for( size_t byte = 0; byte < len; byte++ )
	{
		o << std::setw(2) << std::hex << (size_t)data[byte];

		if( (byte & (0x40 -1)) == (0x40 -1) )
		{
			o << "\n";
		}
		else if( (byte & (0x8 -1)) == (0x8 -1) )
		{
			o << " ";
		}
	}

	o.flags( backup_flags );
}

