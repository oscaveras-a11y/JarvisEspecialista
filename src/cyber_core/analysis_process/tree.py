"""Lifecycle containment only: Windows Job Objects and POSIX process groups."""
import os
import signal
import time


class PosixTree:
    def __init__(self, process):
        self.pid = process.pid

    def close(self):
        if self.pid is not None:
            try:
                os.killpg(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.pid = None


class WindowsTree:
    def __init__(self, process):
        import ctypes
        from ctypes import wintypes
        class Basic(ctypes.Structure):
            _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong),
                        ('PerJobUserTimeLimit', ctypes.c_longlong),
                        ('LimitFlags', wintypes.DWORD),
                        ('MinimumWorkingSetSize', ctypes.c_size_t),
                        ('MaximumWorkingSetSize', ctypes.c_size_t),
                        ('ActiveProcessLimit', wintypes.DWORD),
                        ('Affinity', ctypes.c_size_t),
                        ('PriorityClass', wintypes.DWORD),
                        ('SchedulingClass', wintypes.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ('ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                         'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]
        class Extended(ctypes.Structure):
            _fields_ = [('BasicLimitInformation', Basic), ('IoInfo', IO),
                        ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                        ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.SetInformationJobObject.restype = wintypes.BOOL
        self.api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.api.OpenProcess.restype = wintypes.HANDLE
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.AssignProcessToJobObject.restype = wintypes.BOOL
        self.api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.TerminateJobObject.restype = wintypes.BOOL
        self.api.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        self.api.QueryInformationJobObject.restype = wintypes.BOOL
        self.api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.api.WaitForSingleObject.restype = wintypes.DWORD
        self.api.CreateIoCompletionPort.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.c_size_t, wintypes.DWORD]
        self.api.CreateIoCompletionPort.restype = wintypes.HANDLE
        self.api.GetQueuedCompletionStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                                                       ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_void_p),
                                                       wintypes.DWORD]
        self.api.GetQueuedCompletionStatus.restype = wintypes.BOOL
        self.port, self.assigned = None, False
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            info = Extended()
            info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE, no breakaway
            if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            # Associate while the job is empty, so shutdown notifications include
            # members born after our handle snapshot.
            self.port = self.api.CreateIoCompletionPort(wintypes.HANDLE(-1), None, 0, 1)
            if not self.port:
                raise ctypes.WinError(ctypes.get_last_error())
            class Association(ctypes.Structure):
                _fields_ = [('CompletionKey', ctypes.c_void_p), ('CompletionPort', wintypes.HANDLE)]
            association = Association(1, self.port)
            if not self.api.SetInformationJobObject(self.handle, 7, ctypes.byref(association), ctypes.sizeof(association)):
                raise ctypes.WinError(ctypes.get_last_error())
            handle = self.api.OpenProcess(0x0100 | 0x0001, False, process.pid)  # SET_QUOTA | TERMINATE
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                if not self.api.AssignProcessToJobObject(self.handle, handle):
                    raise ctypes.WinError(ctypes.get_last_error())
                self.assigned = True
            finally:
                self.api.CloseHandle(handle)
        except BaseException:
            self.close()
            raise

    def close(self):
        if not self.handle:
            return
        import ctypes
        handle, self.handle = self.handle, None
        members = []
        try:
            # Hold SYNCHRONIZE handles before termination. An exit code alone can
            # become visible before process termination and handle cleanup finish.
            capacity = 8192
            while True:
                data = ctypes.create_string_buffer(capacity)
                if self.api.QueryInformationJobObject(handle, 3, data, capacity, None):
                    break
                error = ctypes.get_last_error()
                if error != 234 or capacity >= 1048576:  # ERROR_MORE_DATA
                    raise ctypes.WinError(error)
                capacity *= 2
            count = ctypes.c_uint32.from_buffer(data, 4).value
            if 8 + count * ctypes.sizeof(ctypes.c_size_t) > capacity:
                raise OSError('Invalid process membership response')
            identifiers = (ctypes.c_size_t * count).from_buffer(data, 8)
            for pid in identifiers:
                member = self.api.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
                if member:
                    members.append(member)
                elif ctypes.get_last_error() != 87:  # Already-exited PID
                    raise ctypes.WinError(ctypes.get_last_error())
            if not self.api.TerminateJobObject(handle, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            deadline = time.monotonic() + 5
            for member in members:
                remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                outcome = self.api.WaitForSingleObject(member, remaining_ms)
                if outcome == 258:
                    raise OSError('Analysis process termination did not finish in time')
                if outcome != 0:
                    raise ctypes.WinError(ctypes.get_last_error())
            for member in members:
                self.api.CloseHandle(member)
            members.clear()
            if self.assigned and self.port:
                from ctypes import wintypes
                message, key, overlapped = wintypes.DWORD(), ctypes.c_size_t(), ctypes.c_void_p()
                while True:
                    remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                    if remaining_ms == 0:
                        raise OSError('Analysis job termination could not be confirmed')
                    received = self.api.GetQueuedCompletionStatus(self.port, ctypes.byref(message),
                                ctypes.byref(key), ctypes.byref(overlapped), remaining_ms)
                    if not received:
                        raise ctypes.WinError(ctypes.get_last_error())
                    if key.value == 1 and message.value == 4:  # ACTIVE_PROCESS_ZERO
                        break
        finally:
            for member in members:
                self.api.CloseHandle(member)
            # KILL_ON_JOB_CLOSE is retained even if enumeration/wait fails.
            self.api.CloseHandle(handle)
            if self.port:
                self.api.CloseHandle(self.port)
                self.port = None


def attach(process):
    return WindowsTree(process) if os.name == 'nt' else PosixTree(process)
