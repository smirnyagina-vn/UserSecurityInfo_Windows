#pragma once

#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "netapi32.lib")

#include <windows.h>
#include <lm.h>
#include <iostream>
#include <iomanip>
#include <lsalookup.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <winbase.h>
#include <string>

using namespace std;

#define CLEAR_INPUT()	wcin.sync();\
				wcin.clear();\
				fflush(stdin)

#define MAX_STRING_LENGTH 128
#define MAX_PRIVILEGE_INDEX 36

class WinSecApp
{
private:

    DWORD USER_INFO_LEVEL = 1;
    DWORD GROUP_INFO_LEVEL = 2;
    DWORD LOCAL_GROUP_INFO_LEVEL = 0;
    DWORD MAX_USERS = 100;
    DWORD MAX_GROUPS = 100;
    
    DWORD usersAmount;
    DWORD localGroupsAmount;
    DWORD globalGroupsAmount;

    USER_INFO_1* winUsersArray;
    GROUP_INFO_3* winGlobalGroupsArray;
    LOCALGROUP_INFO_0* winLocalGroupsArray;

	PSID* winUsersSID;
    PSID* winLocalGroupsSID;
    PSID* winGlobalGroupsSID;

public:


    WinSecApp();
    ~WinSecApp();

    void CreateBase();
    void UpdateBase();
    void CleanBase();

    void RunMenu();

    void PrintListOfUsers();
    void PrintListOfLocalGroups();
    void PrintListOfGlobalGroups();

    PSID GetUserSID(LPCTSTR userName);
    void GetUserLevel(DWORD userPrivelege);
    void GetUserLocalGroups(LPCTSTR userName);
    void GetUserGlobalGroups(LPCTSTR userName);
    void GetUserPrivileges(int userIndex);
    void AddUser();
    void DeleteUser();
    void AddUserPrivilege();
    void RemoveUserPrivilege();


    void AddLocalGroup();
    void DelLocalGroup();
    void AddUserToLocalGroup();
    void DelUserFromLocalGroup();
    
    void AddGroupPrivilege();
    void DelGroupPrivilege();
    void GetGroupPrivileges(int groupIndex, bool groupType);//true - local, false - global

    void AddGlobalGroup();
    void DelGlobalGroup();
    void AddUserToGlobalGroup();
    void DelUserFromGlobalGroup();

};