#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>

#include <tchar.h>
#include <stdio.h>

//------ ExitWithMessage ------
//
// Exits the process with the specified exit code after printing the provided
// error message
//
VOID __declspec(noreturn) ExitWithMessage(DWORD exitCode, LPTSTR message) {
  printf(message);
  ExitProcess(exitCode);
}

//------ ExitWithError ------
//
// Exit the process with the specified error code as exit code and an
// corresponding error message
//
VOID __declspec(noreturn) ExitWithError(DWORD error) {
  LPTSTR errorText = NULL;

  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                error,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&errorText,
                0,
                NULL);

  ExitWithMessage(error, errorText);
}

//------ ExitWithLastError ------
//
// Exits the process with the last Windows error as exit code and an
// corresponding error message
//
VOID __declspec(noreturn) ExitWithLastError() {
  DWORD error = GetLastError();
  ExitWithError(error);
}

//------ IsUserAdmin ------
//
// Checks if the process user has administrator privileges
//
BOOL IsUserAdmin() {
  BOOL result;
  PSID adminGroup;
  SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

  if (!AllocateAndInitializeSid(&ntAuthority,
                                2,
                                SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0,
                                &adminGroup))
    ExitWithLastError();


  if (!CheckTokenMembership(NULL, adminGroup, &result))
    ExitWithLastError();

  return result;
}

//------ RestartElevated ------
//
// Restarts the process with admin rights via the shell and UAC.
// The restarted process will retreive the same arguments with an additional
// leading argument providing the process id of this process. With this id, it
// can attach itself to the current console.
//
// This function blocks until the started process finished and returns the
// exit code of it.
//
INT RestartElevated(DWORD argc, TCHAR* argv[]) {
  SHELLEXECUTEINFO sei;
  DWORD i, exitCode;
  size_t argumentsLength;
  TCHAR* arguments;
  TCHAR additionalArgument[256];
  DWORD processId = GetCurrentProcessId();

  _stprintf(additionalArgument, _T("/consoleproc:%d"), processId);
  argumentsLength = _tcslen(additionalArgument);
  for (i = 1; i < argc; ++i)
    argumentsLength += _tcslen(argv[i]) + 1;
  arguments = (TCHAR*)malloc((argumentsLength + 1) * sizeof(TCHAR));
  if (arguments == NULL)
    ExitWithMessage(EXIT_FAILURE, _T("Out of memory"));

  _tcscpy(arguments, additionalArgument);
  for (i = 1; i < argc; ++i) {
    _tcscat(arguments, _T(" "));
    _tcscat(arguments, argv[i]);
  }

  sei.cbSize = sizeof(SHELLEXECUTEINFO);
  sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
  sei.hwnd = NULL;
  sei.lpVerb = _T("runas");
  sei.lpFile = argv[0];
  sei.lpParameters = arguments;
  sei.lpDirectory = NULL;
  sei.nShow = SW_NORMAL;

  if (!ShellExecuteEx(&sei))
    ExitWithLastError();

  free(arguments);

  if (WaitForSingleObject(sei.hProcess, INFINITE) != WAIT_OBJECT_0)
    ExitWithLastError();

  if (!GetExitCodeProcess(sei.hProcess, &exitCode))
    ExitWithLastError();

  return exitCode;
}

//------ ReplaceConsole ------
//
// Removes the current attached console host (if any exists) and attaches to
// the console host of the provided process,
//
VOID ReplaceConsole(DWORD processId) {
  if (GetConsoleWindow() != NULL) {
    if (!FreeConsole())
      ExitWithLastError();
  }

  if (AttachConsole(processId) != TRUE)
    ExitWithLastError();
}

//------ ExecuteArguments ------
//
// Creates a new process executing the provided arguments. The process will
// inherit the IO handles from this process.
//
// If the arguments contain an '/consoleproc' argument providing a process
// id as attached by the 'RestartElevated' function it will use the id to
// replace the current console host with the one of parent process.
//
// This function blocks until the started process finished and returns the
// exit code of it.
//
INT ExecuteArguments(DWORD argc, TCHAR* argv[]) {
  PROCESS_INFORMATION pi;
  STARTUPINFO si;
  DWORD i, parentProcessId;
  size_t argumentsLength;
  TCHAR* arguments;

  if (argc < 2)
    ExitWithMessage(EXIT_FAILURE, _T("Missing arguments"));

  parentProcessId = 0;
  if (_stscanf(argv[1], _T("/consoleproc:%d"), &parentProcessId) == 1)
    ReplaceConsole(parentProcessId);

  argumentsLength = 0;
  for (i = parentProcessId != 0 ? 3 : 2; i < argc; ++i)
    argumentsLength += _tcslen(argv[i]) + 1;

  arguments = (TCHAR*)malloc((argumentsLength + 1) * sizeof(TCHAR));
  if (arguments == NULL)
    ExitWithMessage(EXIT_FAILURE, _T("Out of memory"));
  ZeroMemory(arguments, (argumentsLength + 1) * sizeof(TCHAR));

  for (i = parentProcessId != 0 ? 3 : 2; i < argc; ++i) {
    _tcscat(arguments, _T(" "));
    _tcscat(arguments, argv[i]);
  }

  ZeroMemory(&pi, sizeof(pi));

  si.cb = sizeof(STARTUPINFO);
  si.lpReserved = NULL;
  si.lpDesktop = NULL;
  si.lpTitle = NULL;
  si.dwFlags = STARTF_USESTDHANDLES;
  si.cbReserved2 = 0;
  si.lpReserved2 = NULL;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

  if (!CreateProcess(parentProcessId != 0 ? argv[2] : argv[1],
                     arguments,
                     NULL,
                     NULL,
                     TRUE,
                     0,
                     NULL,
                     NULL,
                     &si,
                     &pi))
    ExitWithLastError();

  free(arguments);

  if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0)
    ExitWithLastError();

  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  return EXIT_SUCCESS;
}

//------ main ------
//
// If the process user is already elevated, the arguments will exeucted in a
// child process, otherwise the program will restart itself with administrator
// privileges.
//
INT _tmain(INT argc, TCHAR* argv[]) {
  if (IsUserAdmin())
    return ExecuteArguments((DWORD)argc, argv);
  else
    return RestartElevated((DWORD)argc, argv);
}
