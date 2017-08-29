#ifndef TPM_EXCEPTIONS_HXX
#define TPM_EXCEPTIONS_HXX

/*
 *
 * Copyright (C) 2017
 * SUSE Linux GmbH
 * Matthias Gerstner <matthias.gerstner@suse.com>
 *
 */

// C-lib
#include <errno.h>
#include <string.h>

// C++-lib
#include <exception>
#include <sstream>

// tpm-util
#include "tpm_trousers.hxx"

/**
 * \brief
 * 	Exception class that wraps the TrouSerS error handling
 **/
class TpmException :
	public std::exception
{
public: // functions

	/**
	 * \param[in] res
	 *	The error code received from TrouSerS
	 * \param[in] action
	 * 	Human readable string which kind of operation failed
	 **/
	TpmException(TSS_RESULT res, const std::string &action) :
		m_res(res), m_action(action)
	{
	}

	const char* what() const throw() override
	{
		std::stringstream ss;
		m_msg.clear();
		ss << "Action \"" << m_action << "\" failed with \""
			<< Trspi_Error_String(m_res) << "\" (" << m_res << ")";
		m_msg = ss.str();
		return m_msg.c_str();
	}

protected: // data

	TSS_RESULT m_res;
	std::string m_action;
	mutable std::string m_msg;
};

/**
 * \brief
 * 	Exception class that wraps C library / system call errors
 **/
class SysError :
	public std::exception
{
public: // functions

	/**
	 * \note
	 * 	Obtains the current errno implicitly
	 * \param[in] action
	 * 	Human readable string describing the action that failed
	 **/
	explicit SysError(const std::string &action) :
		m_action(action),
		m_errno(errno)
	{}

	const char* what() const throw() override
	{
		std::stringstream ss;
		m_msg.clear();
		ss << "System/library call \"" << m_action << "\" failed with \""
			<< strerror(m_errno) << "\" (" << m_errno << ")";
		m_msg = ss.str();
		return m_msg.c_str();
	}

protected: // data

	std::string m_action;
	int m_errno;
	mutable std::string m_msg;
};

/**
 * \brief
 * 	Exception class for logical / user errors
 **/
class UsageError :
	public std::exception
{
public:
	explicit UsageError(const std::string &error) :
		m_error(error)
	{}

	const char *what() const throw() override
	{
		return m_error.c_str();
	}
protected:
	std::string m_error;
};

#endif // inc. guard

