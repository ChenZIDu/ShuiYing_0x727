#pragma once
#include "tou.h"
#define BUFFSIZE 1024


class LdapApi
{
public:
	// 构造函数
	LdapApi(std::wstring Host, PWCHAR UserName, PWCHAR Password, HANDLE DelegFile);

	// ldap 连接
	int connect();

	// 委派漏洞（基于资源的约束委派）
	int delegationVul(PWSTR pMyFilter, PWCHAR pMyAttributes[]);

	// 基于资源的约束委派 Resource-based constrained delegation
	void RBCD();

	// 约束委派
	void CD();
	void CD1();

	// 非约束委派 unconstrained delegation
	void ud();
	void ud1();
	void cve_2022_33679();

private:
	std::wstring sHost;
	PWCHAR pUserName;
	PWCHAR pPassword;
	HANDLE hDelegFile;
	PWSTR pMyDN;
	LDAP* pLdapConnection;
	std::wstring wsHost;
};

