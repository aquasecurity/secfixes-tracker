from ctypes import cdll


VersionUnknown = 0
VersionEqual = 1
VersionLess = 2
VersionGreater = 4
VersionFuzzy = 8


libapk = cdll.LoadLibrary('libapk.so.3.12.0')


def do_compare(ver1: str, ver2: str, ops: int):
    return (libapk.apk_version_compare(ver1, ver2) & ops) == ops


def do_compare_fuzzy(ver1: str, ver2: str, ops: int):
    return (libapk.apk_version_compare(ver1, ver2) & ops) != 0


class APKVersion:
    def __init__(self, version: str):
        self.version = version

    def __repr__(self):
        return f'<APKVersion {self.version}>'

    def __eq__(self, other):
        return do_compare(self.version, other.version, VersionEqual)

    def __ne__(self, other):
        return do_compare(self.version, other.version, VersionEqual)

    def __lt__(self, other):
        return do_compare(self.version, other.version, VersionLess)

    def __le__(self, other):
        return do_compare_fuzzy(self.version, other.version, VersionLess | VersionEqual)

    def __gt__(self, other):
        return do_compare(self.version, other.version, VersionGreater)

    def __ge__(self, other):
        return do_compare_fuzzy(self.version, other.version, VersionGreater | VersionEqual)