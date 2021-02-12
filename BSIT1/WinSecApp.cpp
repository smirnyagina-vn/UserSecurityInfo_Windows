#include "WinSecApp.h"


const wchar_t* g_PrivilegeArray[] =
{
    TEXT("SeAssignPrimaryTokenPrivilege"),
    TEXT("SeAuditPrivilege"),
    TEXT("SeBackupPrivilege"),
    TEXT("SeChangeNotifyPrivilege"),
    TEXT("SeCreateGlobalPrivilege"),
    TEXT("SeCreatePagefilePrivilege"),
    TEXT("SeCreatePermanentPrivilege"),
    TEXT("SeCreateSymbolicLinkPrivilege"),
    TEXT("SeCreateTokenPrivilege"),
    TEXT("SeDebugPrivilege"),
    TEXT("SeEnableDelegationPrivilege"),
    TEXT("SeImpersonatePrivilege"),
    TEXT("SeIncreaseBasePriorityPrivilege"),
    TEXT("SeIncreaseQuotaPrivilege"),
    TEXT("SeIncreaseWorkingSetPrivilege"),
    TEXT("SeLoadDriverPrivilege"),
    TEXT("SeLockMemoryPrivilege"),
    TEXT("SeMachineAccountPrivilege"),
    TEXT("SeManageVolumePrivilege"),
    TEXT("SeProfileSingleProcessPrivilege"),
    TEXT("SeRelabelPrivilege"),
    TEXT("SeRemoteShutdownPrivilege"),
    TEXT("SeRestorePrivilege"),
    TEXT("SeSecurityPrivilege"),
    TEXT("SeShutdownPrivilege"),
    TEXT("SeSyncAgentPrivilege"),
    TEXT("SeSystemEnvironmentPrivilege"),
    TEXT("SeSystemProfilePrivilege"),
    TEXT("SeSystemtimePrivilege"),
    TEXT("SeTakeOwnershipPrivilege"),
    TEXT("SeTcbPrivilege"),
    TEXT("SeTimeZonePrivilege"),
    TEXT("SeTrustedCredManAccessPrivilege"),
    TEXT("SeUnsolicitedInputPrivilege"),
    TEXT("SeUndockPrivilege"),
    TEXT("SeInteractiveLogonRight"),
    TEXT("SeNetworkLogonRight")
};


bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
    DWORD dwLen = 0;

    if (NULL == pLsaString)
        return FALSE;

    if (NULL != pwszString)
    {
        dwLen = wcslen(pwszString);
        if (dwLen > 0x7ffe)
            return FALSE;
    }

    pLsaString->Buffer = (WCHAR*)pwszString;
    pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
    pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

    return TRUE;
}


WinSecApp::WinSecApp() {

    CreateBase();
}


WinSecApp::~WinSecApp() {

    NetApiBufferFree(winUsersArray);
    NetApiBufferFree(winGlobalGroupsArray);
    NetApiBufferFree(winLocalGroupsArray);
    CleanBase();
}


void WinSecApp::CreateBase() {

    NET_API_STATUS usersInfoResult;
    NET_API_STATUS globalGroupsInfoResult;
    NET_API_STATUS localGroupsInfoResult;

    if (winUsersArray != NULL)//may be delete
        winUsersArray = NULL;

    winUsersArray = new USER_INFO_1[MAX_USERS];
    
    DWORD dwprefmaxlen = MAX_PREFERRED_LENGTH;
    DWORD dwtotalentries;
    DWORD dwfilter = 0;

    usersInfoResult = NetUserEnum(NULL, USER_INFO_LEVEL, dwfilter, (LPBYTE*)&winUsersArray, dwprefmaxlen, &usersAmount, &dwtotalentries, NULL);
    globalGroupsInfoResult = NetGroupEnum(NULL, GROUP_INFO_LEVEL, (LPBYTE*)&winGlobalGroupsArray, dwprefmaxlen, &globalGroupsAmount, &dwtotalentries, NULL);
    localGroupsInfoResult = NetLocalGroupEnum(NULL, LOCAL_GROUP_INFO_LEVEL, (LPBYTE*)&winLocalGroupsArray, dwprefmaxlen, &localGroupsAmount, &dwtotalentries, NULL);

    winUsersSID = new PSID[MAX_USERS];
    winLocalGroupsSID = new PSID[MAX_GROUPS];
    winGlobalGroupsSID = new PSID[MAX_GROUPS];

    for (int i = 0; i < usersAmount; i++)
        winUsersSID[i] = GetUserSID(winUsersArray[i].usri1_name);
    
    for (int i = 0; i < localGroupsAmount; i++)
        winLocalGroupsSID[i] = GetUserSID(winLocalGroupsArray[i].lgrpi0_name);

    for (int i = 0; i < globalGroupsAmount; i++)
        winGlobalGroupsSID[i] = GetUserSID(winGlobalGroupsArray[i].grpi3_name);

}


void WinSecApp::UpdateBase() {

    CleanBase();
    CreateBase();
}


void WinSecApp::CleanBase() {

    free(winUsersSID);
    free(winGlobalGroupsSID);
    free(winLocalGroupsSID);
    //free(winGroupsArray);
    //free(winUsersArray);
}


LSA_HANDLE GetPolicyHandle()
{
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    USHORT SystemNameLength;
    LSA_UNICODE_STRING lusSystemName;
    NTSTATUS ntsResult;
    LSA_HANDLE lsahPolicyHandle;

    // Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    //Initialize an LSA_UNICODE_STRING to the server name.
    SystemNameLength = wcslen(L"");
    lusSystemName.Buffer = NULL;
    lusSystemName.Length = SystemNameLength * sizeof(WCHAR);
    lusSystemName.MaximumLength = (SystemNameLength + 1) * sizeof(WCHAR);

    // Get a handle to the Policy object.
    ntsResult = LsaOpenPolicy(
        &lusSystemName,    //Name of the target system.
        &ObjectAttributes, //Object attributes.
        POLICY_ALL_ACCESS, //Desired access permissions.
        &lsahPolicyHandle  //Receives the policy handle.
    );

    return lsahPolicyHandle;
}


void WinSecApp::RunMenu() {

    int choice = 0;

    while (choice != 20)
    {
        system("cls");

        cout << "Windows Security App" << endl
            << "1 - Get the list of users" << endl
            << "2 - Get the list of local groups" << endl
            
            << "\n3 - Add user" << endl
            << "4 - Delete user" << endl
            << "5 - Add user privilege" << endl
            << "6 - Delete user privilege" << endl
            
            << "\n7 - Get the list of global groups" << endl
            
            << "\n8 - Add local group" << endl
            << "9 - Del local group" << endl
            << "10 - Add user to local group" << endl
            << "11 - Del user from local group" << endl
            
            << "\n12 - Add group privileges" << endl
            << "13 - Del group privileges" << endl

            //<< "\n14 - Add global group" << endl
            //<< "15 - Del global group" << endl
            //<< "16 - Add user to global group" << endl
            //<< "17 - Del user from global group" << endl
            
            << "\n20 - Exit" << endl;

        cout << endl << "Enter the number of command: ";
        cin >> choice;

        switch (choice)
        {
        case 1:
            PrintListOfUsers();
            break;
        case 2:
            PrintListOfLocalGroups();
            break;
        case 3:
            AddUser();
            break;
        case 4:
            DeleteUser();
            break;
        case 5:
            AddUserPrivilege();
            break;
        case 6:
            RemoveUserPrivilege();
            break;
        case 7:
            PrintListOfGlobalGroups();
            break;
        case 8:
            AddLocalGroup();
            break;
        case 9:
            DelLocalGroup();
            break;
        case 10:
            AddUserToLocalGroup();
            break;
        case 11:
            DelUserFromLocalGroup();
            break;
        case 12:
            AddGroupPrivilege();
            break;
        case 13:
            DelGroupPrivilege();
            break;
        case 14:
            AddGlobalGroup();
            break;
        case 15:
            DelGlobalGroup();
            break;
        case 16:
            AddUserToGlobalGroup();
            break;
        case 17:
            DelUserFromGlobalGroup();
            break;
        case 20:
            return;
        default:
            cout << "Wrong command. Try again." << endl;
            break;
        }
        system("pause");
    }
}


void WinSecApp::PrintListOfUsers() {

    cout << endl << "___Users List___" << endl;
    string dividingLine = "------------------------------------------------------------------------------\n";
    LPWSTR stringSID;
    DWORD privilegeAmount = 0;
    PLSA_UNICODE_STRING userPrivilegeArray;

    for (int i = 0; i < usersAmount; i++)
    {
        cout << endl;
        cout << "#" << i << endl;
        cout << setw(30) << left << "User name:";
        wcout << winUsersArray[i].usri1_name << endl;
        cout << setw(30) << left << "User SID:";
        ConvertSidToStringSidW(winUsersSID[i], &stringSID);
        wcout << stringSID << endl;
        cout << setw(30) << left << "User Privileges:";
        GetUserPrivileges(i);        
        cout << setw(30) << left << "User`s Local Groups:";
        GetUserLocalGroups(winUsersArray[i].usri1_name);
        cout << setw(30) << left << "User`s Global Groups:";
        GetUserGlobalGroups(winUsersArray[i].usri1_name);
        cout << setw(30) << left << "User`s Level:";
        GetUserLevel(winUsersArray[i].usri1_priv);
        cout << dividingLine;
    }
}


PSID WinSecApp::GetUserSID(LPCTSTR userName)
{
    DWORD dwSidLength = 0, dwLengthOfDomainName = 0, dwRetCode = 0;
    SID_NAME_USE typeOfSid;
    PSID lpSid = NULL;
    LPTSTR lpDomainName = NULL;

    if (!LookupAccountName(NULL, userName, NULL, &dwSidLength, NULL, &dwLengthOfDomainName, &typeOfSid)) {

        dwRetCode = GetLastError();
        //We don`t know the length of SID, that`s why we call this function twice
        if (dwRetCode == ERROR_INSUFFICIENT_BUFFER) {
            lpSid = (SID*) new char[dwSidLength];
            lpDomainName = (LPTSTR) new wchar_t[dwLengthOfDomainName];
        }
        else {
            cout << "Lookup account name failed: " << GetLastError() << endl;
            return NULL;
        }
    }

    if (!LookupAccountName(NULL, userName, lpSid, &dwSidLength, lpDomainName, &dwLengthOfDomainName, &typeOfSid)) {

        cout << "Lookup account name failed: " << GetLastError() << endl;
        return NULL;
    }
    return lpSid;
}


void WinSecApp::GetUserLevel(DWORD userPrivelege)
{
    if (userPrivelege == USER_PRIV_GUEST)
        cout << "Guest";
    else
        if (userPrivelege == USER_PRIV_USER)
            cout << "User";
        else
            if (userPrivelege == USER_PRIV_ADMIN)
                cout << "Admin";
    cout << endl;
}


void WinSecApp::GetUserPrivileges(int userIndex)
{

    LPUSER_INFO_0 pBuf = NULL;
    USER_INFO_1* tmpBuf;

    LPGROUP_USERS_INFO_1 pBuf1;
    LPLOCALGROUP_USERS_INFO_0 pBuf2;
    LPUSER_INFO_4 pTmpBuf1;
    NET_API_STATUS nStatus;
    NET_API_STATUS nStatusLG;
    DWORD dwEntriesRead = 0;
    DWORD dwEntriesRead1 = 0;
    DWORD dwEntriesReadLG = 0;
    DWORD dwTotalEntriesLG = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    DWORD i = MAX_COMPUTERNAME_LENGTH + 1;
    DWORD dwTotalCount = 0;
    wchar_t pszServerName[MAX_COMPUTERNAME_LENGTH + 1];
    GetComputerNameW(pszServerName, &i);


    NetUserGetInfo((LPCWSTR)pszServerName, winUsersArray[userIndex].usri1_name, 4, (LPBYTE*)&pTmpBuf1);
    wchar_t priv[100];
            
    LPWSTR sid;
    ConvertSidToStringSidW(winUsersSID[userIndex], &sid);

    NTSTATUS ntsResult;
    LSA_OBJECT_ATTRIBUTES ObjAttributes;
    LSA_HANDLE lsahPolicyHandle;
    ULONG count = 0;
    ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));
    PSID sid1 = winUsersSID[userIndex];
    ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_LOOKUP_NAMES, &lsahPolicyHandle);
    PLSA_UNICODE_STRING rights;
    ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, sid1, &rights, &count);
    ULONG u = LsaNtStatusToWinError(ntsResult);
    LPLOCALGROUP_INFO_0 lgroups = NULL;
    nStatusLG = NetUserGetLocalGroups((LPCWSTR)pszServerName, winUsersArray[userIndex].usri1_name, 0, LG_INCLUDE_INDIRECT, 
                                        (LPBYTE*)&pBuf2, MAX_PREFERRED_LENGTH, &dwEntriesReadLG, &dwTotalEntriesLG);
            
    if (ntsResult == ERROR_SUCCESS)
    {
        if (count)
            for (int k = 0; k < count; k++)
            {
                if (k + 1 < count)
                    wprintf(L"%s, ", rights->Buffer);
                else
                    wprintf(L"%s", rights->Buffer);
                rights++;
            }
        else
            printf("Отсутствуют");
    }
    else {
        DWORD dwEntriesRead = 0;
        DWORD dwTotalEntries = 0;
        DWORD dwResumeHandle = 0;
        nStatus = NetLocalGroupEnum(pszServerName, 0, (LPBYTE*)&lgroups, MAX_PREFERRED_LENGTH, 
                                    &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
            
        if (dwEntriesReadLG != 0 && nStatus == NERR_Success && nStatusLG == NERR_Success) 
        {
            LPLOCALGROUP_USERS_INFO_0 pTmpBuf = pBuf2;
            for (int i = 0; i < dwEntriesRead; i++) {
                if (lstrcmpW(lgroups->lgrpi0_name, pTmpBuf->lgrui0_name) == 0) {
                    LSA_HANDLE lsahPolicyHandle;
                    LSA_OBJECT_ATTRIBUTES ObjAttributes;
                    PSID sid1 = GetUserSID(lgroups->lgrpi0_name);
                    ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));
                    ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
                    PLSA_UNICODE_STRING rights;
                    ULONG count = 0;
                    ntsResult = LsaEnumerateAccountRights(lsahPolicyHandle, sid1, &rights, &count);
                    if (ntsResult == ERROR_SUCCESS)
                    {
                        if (count)
                            for (int k = 0; k < count; k++)
                            {
                                if (k + 1 < count)
                                    wprintf(L"%s, ", rights->Buffer);
                                else
                                    wprintf(L"%s", rights->Buffer);
                                rights++;
                            }
                        else
                            printf("Отсутствуют");
                    }
                }
                lgroups++;
            }
        }
    }

    cout << endl;    

}


void WinSecApp::GetUserLocalGroups(LPCTSTR userName)
{
    LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
    DWORD dwEntriesRead, dwTotalEntries, dwTotalCount = 0, i;

    NET_API_STATUS nStatus = NetUserGetLocalGroups(NULL, userName, 0, LG_INCLUDE_INDIRECT,
                                                  (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries);

    if (nStatus == NERR_Success) {

        for (i = 0; i < dwEntriesRead; i++) {

            if (pBuf == NULL) {
                cout << "An access violation has occurred";
                break;
            }
            wcout << pBuf->lgrui0_name << " ";
            pBuf++;
            dwTotalCount++;
        }     
    }
    else
        cout << "A system error has occurred";

    if (pBuf != NULL) {
        NetApiBufferFree(pBuf);
        pBuf = NULL;
    }

    cout << endl;
}


void WinSecApp::GetUserGlobalGroups(LPCTSTR userName)
{
    DWORD dwEntriesRead = 0;
    DWORD dwtotalentries;
    LPGROUP_USERS_INFO_1 userGroups;
    NetUserGetGroups(NULL, userName, 1, (LPBYTE*)&userGroups, 
                     MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwtotalentries);

    for (int i = 0; i < dwEntriesRead; i++)
        wcout << userGroups[i].grui1_name << " ";

    cout << endl;
}


void WinSecApp::AddUser()
{
    TCHAR userName[MAX_STRING_LENGTH] = { 0 };
    TCHAR userPassword[MAX_STRING_LENGTH] = { 0 };

    cout << "Enter name of new user: ";
    wcin >> userName;
    cout << "Enter password of new user: ";
    wcin >> userPassword;

    USER_INFO_1 userInfo;
    NET_API_STATUS nStatus = NERR_Success;
    ZeroMemory(&userInfo, sizeof(USER_INFO_1));
    userInfo.usri1_name = userName;
    userInfo.usri1_password = userPassword;
    userInfo.usri1_priv = USER_PRIV_USER;
    userInfo.usri1_flags = UF_NORMAL_ACCOUNT | UF_SCRIPT;

    nStatus = NetUserAdd(NULL, 1, (PBYTE)&userInfo, NULL);

    if (nStatus == NERR_Success)
        cout << "Success" << endl;
    else
        cout << "Error: " << GetLastError() << endl;

    UpdateBase();
}


void WinSecApp::DeleteUser()
{
    unsigned int index;
    cout << "Enter the index of user, which you want to delete: ";
    cin >> index;

    NET_API_STATUS nStatus = NetUserDel(NULL, winUsersArray[index].usri1_name);

    if (nStatus == NERR_Success)
        cout << "Success" << endl;
    else
        cout << "Error: " << GetLastError() << endl;

    UpdateBase();
}


void WinSecApp::AddUserPrivilege()
{
    unsigned int index;
    cout << "Enter user`s index: ";
    cin >> index;

    LSA_HANDLE lsahPolicyHandle;
    LSA_OBJECT_ATTRIBUTES ObjAttributes;
    ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

    NTSTATUS nStatus = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
    if (nStatus != NULL)
        cout << "Lsa open policy failed: %d\n" << GetLastError();

    cout << "Privilege list" << endl;
    for (int i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
        wcout << i << " - " << g_PrivilegeArray[i] << endl;

    DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;

    while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX) {

        cout << endl << "Enter index of privilege: ";
        wcin >> privilegeIndex;
    }

    LSA_UNICODE_STRING lsaString;
    InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

    if (LsaAddAccountRights(lsahPolicyHandle, winUsersSID[index], &lsaString, 1))
        cout << "Error: " << GetLastError() << endl;
    else cout << "Success" << endl;
}


void WinSecApp::RemoveUserPrivilege()
{
    unsigned int userIndex;
    cout << "Enter user`s index: ";
    cin >> userIndex;

    DWORD privilegesAmount = 0;
    PLSA_UNICODE_STRING privilegesArray;
    LSA_HANDLE Handle = GetPolicyHandle();
    LsaEnumerateAccountRights(Handle, winUsersSID[userIndex], &privilegesArray, &privilegesAmount);
    LsaClose(Handle);

    if (privilegesAmount > 0) {

        cout << "Privilege list" << endl;
        for (int i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
            wcout << i << " - " << g_PrivilegeArray[i] << endl;
        
        DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;
        while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX) {
            cout << endl << "Enter number of privilege: ";
            wcin >> privilegeIndex;
        }

        LSA_UNICODE_STRING lsaString;
        InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

        LSA_HANDLE pHandle = GetPolicyHandle();
        NTSTATUS nStatus = LsaRemoveAccountRights(pHandle, winUsersSID[userIndex], FALSE, &lsaString, 1);
        LsaClose(pHandle);

        if (LsaNtStatusToWinError(nStatus) == ERROR_SUCCESS)
            cout << "Success" << endl;
        else
            cout << "Error: " << GetLastError() << endl;

    }
    else
        cout << "User doesn't have any privileges" << endl;
}


void WinSecApp::PrintListOfLocalGroups() {

    cout << endl << "___Local Groups List___" << endl;
    string dividingLine = "------------------------------------------------------------------------------\n";
    LPWSTR stringSID;
    DWORD privilegeAmount = 0;
    PLSA_UNICODE_STRING userPrivilegeArray;

    for (int i = 0; i < localGroupsAmount; i++)
    {
        cout << endl;
        cout << "#" << i << endl;
        cout << setw(30) << left << "Group name:";
        wcout << winLocalGroupsArray[i].lgrpi0_name << endl;
        cout << setw(30) << left << "Group SID:";
        ConvertSidToStringSidW(winLocalGroupsSID[i], &stringSID);
        wcout << stringSID << endl;
        cout << setw(30) << left << "Group Privileges:";
        GetGroupPrivileges(i, true);
        cout << dividingLine;
    }
}


void WinSecApp::GetGroupPrivileges(int groupIndex, bool groupType)
{
    NTSTATUS nStatus;
    DWORD rightsAmount;
    PLSA_UNICODE_STRING groupRights;
    LSA_HANDLE pHandle = GetPolicyHandle();
    if (groupType)
        nStatus = LsaEnumerateAccountRights(pHandle, winLocalGroupsSID[groupIndex], &groupRights, &rightsAmount);
    else
        nStatus = LsaEnumerateAccountRights(pHandle, winGlobalGroupsSID[groupIndex], &groupRights, &rightsAmount);

    if (rightsAmount != 0) {
        for (int i = 0; i < rightsAmount; i++)
            wcout << groupRights[i].Buffer << " ";
    }
    wcout << endl;

    LsaClose(pHandle);
    LsaFreeMemory(groupRights);

}


void WinSecApp::AddLocalGroup()
{
    wchar_t groupName[MAX_STRING_LENGTH];
    wcout << "Enter the name of new group: ";
    wcin >> groupName;

    LOCALGROUP_INFO_0 groupInfo;
    groupInfo.lgrpi0_name = groupName;

    NET_API_STATUS status = NetLocalGroupAdd(NULL, 0, (PBYTE)&groupInfo, NULL);
    if (status == NERR_Success)
        cout << "Success" << endl;
    else cout << "Error: " << GetLastError() << endl;

    UpdateBase();
}


void WinSecApp::DelLocalGroup()
{
    wchar_t groupName[MAX_STRING_LENGTH] = { 0 };
    wcout << "Enter the name of group, which you want to delete: ";
    wcin >> groupName;

    NET_API_STATUS status = NetLocalGroupDel(NULL, groupName);
    if (status == NERR_Success)
        cout << "Success" << endl;
    else cout << "Error: " << GetLastError() << endl;

    UpdateBase();
}


void WinSecApp::AddUserToLocalGroup()
{
    int userIndex, groupIndex;
    cout << "Enter the index of group: ";
    cin >> groupIndex;
    cout << "Enter the index of user: ";
    cin >> userIndex;

    if (NetLocalGroupAddMember(NULL, winLocalGroupsArray[groupIndex].lgrpi0_name, winUsersSID[userIndex]) == NERR_Success)
        cout << "Success" << endl;
    else cout << "Error: " << GetLastError() << endl;
    UpdateBase();
}


void WinSecApp::DelUserFromLocalGroup()
{
    int userIndex, groupIndex;
    cout << "Enter the index of group: ";
    cin >> groupIndex;
    cout << "Enter the index of user, that you want to delete from group: ";
    cin >> userIndex;

    if (NetLocalGroupDelMember(NULL, winLocalGroupsArray[groupIndex].lgrpi0_name, winUsersSID[userIndex]) == NERR_Success)
        cout << "Success" << endl;
    else cout << "Error: " << GetLastError() << endl;
    UpdateBase();
}


void WinSecApp::AddGroupPrivilege()
{
    int groupIndex;
    bool groupType;
    cout << "Enter the type of group(1 - local, 0 - global): ";
    cin >> groupType;
    cout << "Enter the index of group: ";
    cin >> groupIndex;

    LSA_HANDLE lsahPolicyHandle;
    LSA_OBJECT_ATTRIBUTES ObjAttributes;
    ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

    NTSTATUS ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
    if (ntsResult != NULL)
        cout << "Lsa open policy failed: " << GetLastError() << endl;

    for (size_t i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
        wcout <<  i << " - " << g_PrivilegeArray[i] << endl;

    DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;
    while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX) {
        cout << "Enter number of privilege: ";
        wcin >> privilegeIndex;
    }

    LSA_UNICODE_STRING lsaString;
    InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

    if (groupType)//if local
    {
        if (LsaAddAccountRights(lsahPolicyHandle, winLocalGroupsSID[groupIndex], &lsaString, 1) != NULL)
            cout << "Error: " << GetLastError() << endl;
        else cout << "Success" << endl;
    }
    else
    {
        if (LsaAddAccountRights(lsahPolicyHandle, winGlobalGroupsSID[groupIndex], &lsaString, 1) != NULL)
            cout << "Error: " << GetLastError() << endl;
        else cout << "Success" << endl;
    }
}


void WinSecApp::DelGroupPrivilege()
{
    int groupIndex;
    bool groupType;
    cout << "Enter the type of group(1 - local, 0 - global): ";
    cin >> groupType;
    cout << "Enter the index of group: ";
    cin >> groupIndex;

    DWORD privilegeAmount = 0;
    PLSA_UNICODE_STRING privilegeArray;
    LSA_HANDLE Handle = GetPolicyHandle();
    if (groupType)
        LsaEnumerateAccountRights(Handle, winLocalGroupsSID[groupIndex], &privilegeArray, &privilegeAmount);
    else 
        LsaEnumerateAccountRights(Handle, winGlobalGroupsSID[groupIndex], &privilegeArray, &privilegeAmount);
    LsaClose(Handle);

    if (privilegeAmount > 0)
    {
        for (size_t i = 0; i <= MAX_PRIVILEGE_INDEX; i++)
            wcout << i << " - " << g_PrivilegeArray[i] << endl;;

        DWORD privilegeIndex = MAX_PRIVILEGE_INDEX + 1;
        while (privilegeIndex < 0 || privilegeIndex > MAX_PRIVILEGE_INDEX) {
            cout << "Enter number of privilege: ";
            wcin >> privilegeIndex;
        }

        LSA_OBJECT_ATTRIBUTES ObjAttributes;
        LSA_HANDLE lsahPolicyHandle;
        ZeroMemory(&ObjAttributes, sizeof(ObjAttributes));

        NTSTATUS ntsResult = LsaOpenPolicy(0, &ObjAttributes, POLICY_ALL_ACCESS, &lsahPolicyHandle);
        if (ntsResult != NULL)
            cout << "Lsa open policy failed: " << GetLastError() << endl;

        LSA_UNICODE_STRING lsaString;
        InitLsaString(&lsaString, g_PrivilegeArray[privilegeIndex]);

        if (groupType)//if local
        {
            if (LsaRemoveAccountRights(lsahPolicyHandle, winLocalGroupsSID[groupIndex], 0, &lsaString, 1) != NULL)
                cout << "Error: " << GetLastError() << endl;
            else cout << "Success" << endl;
        }
        else
        {
            if (LsaRemoveAccountRights(lsahPolicyHandle, winGlobalGroupsSID[groupIndex], 0, &lsaString, 1) != NULL)
                cout << "Error: " << GetLastError() << endl;
            else cout << "Success" << endl;
        }
    }
    else
        cout << "Group doesn't have any privileges" << endl;
}


void WinSecApp::PrintListOfGlobalGroups() {

    cout << endl << "___Global Groups List___" << endl;
    string dividingLine = "------------------------------------------------------------------------------\n";
    LPWSTR stringSID;
    DWORD privilegeAmount = 0;
    PLSA_UNICODE_STRING userPrivilegeArray;

    for (int i = 0; i < globalGroupsAmount; i++)
    {
        cout << endl;
        cout << "#" << i << endl;
        cout << setw(30) << left << "Group name:";
        wcout << winGlobalGroupsArray[i].grpi3_name << endl;
        cout << setw(30) << left << "Group SID:";
        ConvertSidToStringSidW(winGlobalGroupsSID[i], &stringSID);
        wcout << stringSID << endl;
        cout << setw(30) << left << "Group Privileges:";
        GetGroupPrivileges(i, false);
        cout << dividingLine;
    }
}


void WinSecApp::AddGlobalGroup()
{
    wchar_t groupName[MAX_STRING_LENGTH];
    wcout << "Enter the name of new group: ";
    wcin >> groupName;

    GROUP_INFO_3 groupInfo;
    groupInfo.grpi3_name = groupName;

    NET_API_STATUS nStatus = NetGroupAdd(NULL, GROUP_INFO_LEVEL, (PBYTE)&groupInfo, NULL);
    if (nStatus == NERR_Success)
        wcout << "Success" << endl;
    //else wcout << "Error: " << GetLastError() << endl;
    if (nStatus == ERROR_ACCESS_DENIED)
        cout << "ERROR_ACCESS_DENIED" << endl;
    else if (nStatus == NERR_InvalidComputer)
        cout << "NERR_InvalidComputer" << endl;
    else if (nStatus == NERR_NotPrimary)
        cout << "NERR_NotPrimary" << endl;
    else if (nStatus == NERR_GroupExists)
        cout << "NERR_GroupExists" << endl;
    else if (nStatus == NERR_SpeGroupOp)
        cout << "NERR_SpeGroupOp" << endl;
    else if (nStatus == ERROR_ALIAS_EXISTS)
        cout << "ERROR_ALIAS_EXISTS" << endl;
    else if (nStatus == ERROR_INVALID_LEVEL)
        cout << "ERROR_INVALID_LEVEL" << endl;
    else if (nStatus == ERROR_INVALID_PARAMETER)
        cout << "ERROR_INVALID_PARAMETER" << endl;
    else
        cout << "Unknown error" << endl;

    UpdateBase();
}


void WinSecApp::DelGlobalGroup()
{
    wchar_t groupName[MAX_STRING_LENGTH] = { 0 };
    wcout << "Enter the name of group, which you want to delete: ";
    wcin >> groupName;

    NET_API_STATUS status = NetGroupDel(NULL, groupName);
    if (status == NERR_Success)
        cout << "Success" << endl;
    else cout << "Error: " << GetLastError() << endl;

    UpdateBase();
}


void WinSecApp::AddUserToGlobalGroup()
{
    int userIndex, groupIndex;
    cout << "Enter the index of group: ";
    cin >> groupIndex;
    cout << "Enter the index of user: ";
    cin >> userIndex;

    if (NetGroupAddUser(NULL, winGlobalGroupsArray[groupIndex].grpi3_name, winUsersArray[userIndex].usri1_name) == NERR_Success)
        cout << "Success" << endl;
    else cout << "Error: " << GetLastError() << endl;
    UpdateBase();
}


void WinSecApp::DelUserFromGlobalGroup()
{
    int userIndex, groupIndex;
    cout << "Enter the index of group: ";
    cin >> groupIndex;
    cout << "Enter the index of user, that you want to delete from group: ";
    cin >> userIndex;

    if (NetGroupDelUser(NULL, winGlobalGroupsArray[groupIndex].grpi3_name, winUsersArray[userIndex].usri1_name) == NERR_Success)
        cout << "Success" << endl;
    else cout << "Error: " << GetLastError() << endl;
    UpdateBase();
}