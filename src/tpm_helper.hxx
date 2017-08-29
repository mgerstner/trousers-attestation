#ifndef TPM_HELPER_HXX
#define TPM_HELPER_HXX

/*
 *
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 *
 */

#include <string>
#include <vector>
#include <sstream>

/**
 * \brief
 * 	Split a string using the given delimiter
 **/
std::vector<std::string> split(const std::string &s, const char delim)
{
	std::stringstream ss(s);
	std::string item;
	std::vector<std::string> elems;

	while (std::getline(ss, item, delim))
	{
		elems.push_back(std::move(item));
	}
	return elems;
}

/**
 * \brief
 * 	Strip the given character from the beginning/end of the given string
 **/
void strip(std::string &s, const char c = ' ')
{
	while( !s.empty() && s[0] == c )
		s.erase( 0, 1 );

	while( !s.empty() && s[s.size()-1] == c )
		s.pop_back();
}

#endif // inc. guard

