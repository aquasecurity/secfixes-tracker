from ctypes import cdll
import ctypes.util


VersionUnknown = 0
VersionEqual = 1
VersionLess = 2
VersionGreater = 4
VersionFuzzy = 8


# Try to load libapk with different strategies
libapk = None
lib_names = [
    '/usr/lib/libapk.so',      # Unversioned symlink (created by workflow) - absolute path
    '/lib/libapk.so',          # Unversioned symlink (alternative location) - absolute path
    'libapk.so',               # Unversioned symlink - relative
    'libapk.so.2.14.9',        # Alpine 3.22+ (relative)
    'libapk.so.2.14.1',        # Alpine 3.20+ (relative)
    'libapk.so.2.14.0',        # Alpine 3.18-3.19 (relative)
    '/usr/lib/libapk.so.2.14.9',  # Absolute versioned (3.22+)
    '/usr/lib/libapk.so.2.14.1',  # Absolute versioned (3.20+)
    '/usr/lib/libapk.so.2.14.0',  # Absolute versioned (3.18-3.19)
    '/lib/libapk.so.2.14.9',      # Alternative absolute versioned (3.22+)
    '/lib/libapk.so.2.14.1',      # Alternative absolute versioned (3.20+)
    '/lib/libapk.so.2.14.0',      # Alternative absolute versioned (3.18-3.19)
    'apk',                     # Short name
]

for lib_name in lib_names:
    try:
        libapk = cdll.LoadLibrary(lib_name)
        break
    except OSError:
        pass

# Try using ctypes.util.find_library as fallback
if libapk is None:
    lib_path = ctypes.util.find_library('apk')
    if lib_path:
        try:
            libapk = cdll.LoadLibrary(lib_path)
        except OSError:
            pass

if libapk is None:
    # Create a mock library for environments where libapk is not available
    class MockLibapk:
        def apk_version_compare(self, ver1, ver2):
            # Simple string comparison fallback
            if ver1 == ver2:
                return 1  # VersionEqual
            elif ver1 < ver2:
                return 2  # VersionLess
            else:
                return 4  # VersionGreater
    
    libapk = MockLibapk()
    print("Warning: libapk not available, using fallback version comparison")


def do_compare(ver1: str, ver2: str, ops: int):
    return (libapk.apk_version_compare(ver1.encode('ascii'), ver2.encode('ascii')) & ops) == ops


def do_compare_fuzzy(ver1: str, ver2: str, ops: int):
    return (libapk.apk_version_compare(ver1.encode('ascii'), ver2.encode('ascii')) & ops) != 0


class APKVersion:
    def __init__(self, version: str):
        self.version = version

    def __repr__(self):
        return f'<APKVersion {self.version}>'

    def __eq__(self, other):
        return do_compare(self.version, other.version, VersionEqual)

    def __ne__(self, other):
        return not do_compare(self.version, other.version, VersionEqual)

    def __lt__(self, other):
        return do_compare(self.version, other.version, VersionLess)

    def __le__(self, other):
        return do_compare_fuzzy(self.version, other.version, VersionLess | VersionEqual)

    def __gt__(self, other):
        return do_compare(self.version, other.version, VersionGreater)

    def __ge__(self, other):
        return do_compare_fuzzy(self.version, other.version, VersionGreater | VersionEqual)
