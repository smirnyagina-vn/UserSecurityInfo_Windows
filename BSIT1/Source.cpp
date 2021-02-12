#include <iostream>
#include <locale.h>
#include "WinSecApp.h"

using namespace std;


int main()
{
    setlocale(LC_ALL, "Rus");
    WinSecApp winSecApp = WinSecApp();
    winSecApp.RunMenu();
}