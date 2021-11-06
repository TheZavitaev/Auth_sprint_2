from enum import Enum


class Permissions(str, Enum):
    ROLE_WRITE = 'role:write'
    SUSPICIOUS_READ = 'suspicious:read'
